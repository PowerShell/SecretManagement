// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.PowerShell.SecretManagement;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;

namespace Microsoft.PowerShell.CredManStore
{
    /*
    #region Get-Secret

    [Cmdlet(VerbsCommon.Get, "Secret")]
    public sealed class GetSecretCommand : PSCmdlet
    {
        #region Parameters

        [Parameter]
        public string Name { get; set; }

        [Parameter]
        public string VaultName { get; set; }

        [Parameter]
        public Hashtable AdditionalParameters { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (LocalCredManStore.ReadObject(
                name: Name,
                outObject: out object outObject,
                out int errorCode))
            {
                WriteObject(
                    sendToPipeline: outObject,
                    enumerateCollection: false);
                
                return;
            }

            if (errorCode > 0 && errorCode != NativeUtils.ERROR_NOT_FOUND)
            {
                var message = string.Format(CultureInfo.InvariantCulture, 
                    @"Error while retrieving secret from vault {0} : {1}",
                    VaultName,
                    LocalCredManStore.GetErrorMessage(errorCode));

                WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(message),
                        "CredManVaultGetError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        #endregion
    }

    #endregion

    #region Get-SecretInfo

    [Cmdlet(VerbsCommon.Get, "SecretInfo")]
    public sealed class GetSecretInfoCommand : PSCmdlet
    {
        #region Parameters

        [Parameter]
        public string Filter { get; set; }

        [Parameter]
        public string VaultName { get; set; }

        [Parameter]
        public Hashtable AdditionalParameters { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (LocalCredManStore.EnumerateObjectInfo(
                filter: Filter,
                out KeyValuePair<string, SecretType>[] outObjectInfos,
                out int errorCode))
            {
                var secretInfoList = new List<SecretInformation>(outObjectInfos.Length);
                foreach (var item in outObjectInfos)
                {
                    secretInfoList.Add(
                        new SecretInformation(
                            name: item.Key,
                            type: item.Value,
                            vaultName: VaultName));
                }

                WriteObject(
                    sendToPipeline: secretInfoList.ToArray(),
                    enumerateCollection: false);

                return;
            }
            
            if (errorCode > 0 && errorCode != NativeUtils.ERROR_NOT_FOUND)
            {
                var message = string.Format(CultureInfo.InvariantCulture, 
                    @"Error while retrieving secret information from vault {0} : {1}",
                    VaultName,
                    LocalCredManStore.GetErrorMessage(errorCode));

                WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(message),
                        "CredManVaultGetInfoError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        #endregion
    }

    #endregion

    #region Set-Secret

    [Cmdlet(VerbsCommon.Set, "Secret")]
    public sealed class SetSecretCommand : PSCmdlet
    {
        #region Parameters

        [Parameter]
        public string Name { get; set; }

        [Parameter]
        public object Secret { get; set; }

        [Parameter]
        public string VaultName { get; set; }

        [Parameter]
        public Hashtable AdditionalParameters { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (!LocalCredManStore.WriteObject(
                name: Name,
                objectToWrite: Secret,
                out int errorCode))
            {
                var message = string.Format(CultureInfo.InvariantCulture, 
                    @"Error while writing secret to vault {0} : {1}",
                    VaultName,
                    LocalCredManStore.GetErrorMessage(errorCode));

                WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(message),
                        "CredManVaultWriteError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        #endregion
    }

    #endregion

    #region Remove-Secret

    [Cmdlet(VerbsCommon.Remove, "Secret")]
    public sealed class RemoveSecretCommand : PSCmdlet
    {
        #region Parameters

        [Parameter]
        public string Name { get; set; }

        [Parameter]
        public string VaultName { get; set; }

        [Parameter]
        public Hashtable AdditionalParameters { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (!LocalCredManStore.DeleteObject(
                name: Name,
                out int errorCode))
            {
                var message = string.Format(CultureInfo.InvariantCulture, 
                    @"Error while deleting secret from vault {0} : {1}",
                    VaultName,
                    LocalCredManStore.GetErrorMessage(errorCode));

                WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(message),
                        "CredManVaultWriteError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        #endregion
    }

    #endregion

    #region Test-SecretVault
    
    [Cmdlet(VerbsDiagnostic.Test, "SecretVault")]
    public sealed class TestSecretVaultCommand : PSCmdlet
    {
        #region Parameters

        [Parameter]
        public string VaultName { get; set; }

        [Parameter]
        public Hashtable AdditionalParameters { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            // TODO: Implement.
            WriteObject(true);
        }

        #endregion

    }

    #endregion
*/
}
