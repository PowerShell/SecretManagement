---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Unlock-SecretVault

## SYNOPSIS
Unlocks an extension vault so that it can be access in the current session.

## SYNTAX

```
Unlock-SecretVault [-Name] <String> [-Password] <SecureString> [<CommonParameters>]
```

## DESCRIPTION
This cmdlet unlocks an extension vault using the provided Password parameter argument.
This allows a vault that requires password authentication to operate without first having to prompt
the user.
Not all extension vaults require password authentication, in which case this command has no effect.
A warning will be emitted if the extension vault does not support unlocking via password.

## EXAMPLES

### Example 1
```powershell
PS C:\> Unlock-SecretVault -Name SecretStore -Password $SecurePassword
PS C:\> Get-SecretInfo -Vault SecretStore

Name             Type         VaultName
----             ----         ---------
Secret1          SecureString SecretStore
Secret2          SecureString SecretStore
```

This example uses the command to unlock the SecretStore vault.
It then runs the 'Get-SecretInfo' command on the vault without being prompted for the vault
password.

### Example 2
```powershell
PS C:\> Unlock-SecretVault -Name CredMan -Password $SecurePassword
WARNING: Cannot unlock extension vault 'CredMan': The vault does not support the Unlock-SecretVault function.
PS C:\>
```

This example uses the command to unlock the CredMan vault.
But the vault does not support unlocking so the command has no effect.
A warning is displayed informing that CredMan vault does not support unlocking.

## PARAMETERS

### -Name
Name of the vault to unlock.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
Password used to unlock the vault.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
