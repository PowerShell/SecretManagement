---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/unlock-secretvault?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Unlock-SecretVault

## SYNOPSIS
Unlocks an extension vault so that it can be accessed in the current session.

## SYNTAX

```
Unlock-SecretVault [-Name] <String> [-Password] <SecureString> [<CommonParameters>]
```

## DESCRIPTION

This cmdlet unlocks an extension vault using the provided **Password**. This allows a vault that
requires password authentication to operate without first having to prompt the user. Not all
extension vaults require password authentication. The cmdlet returns a warning if the extension
vault doesn't support unlocking via password.

## EXAMPLES

### Example 1

```powershell
Unlock-SecretVault -Name SecretStore -Password $SecurePassword
Get-SecretInfo -Vault SecretStore
```

```Output
Name             Type         VaultName
----             ----         ---------
Secret1          SecureString SecretStore
Secret2          SecureString SecretStore
```

This example uses the command to unlock the `SecretStore` vault. It then runs the `Get-SecretInfo`
command on the vault without being prompted for the vault password.

### Example 2

```powershell
Unlock-SecretVault -Name CredMan -Password $SecurePassword
```

```Output
WARNING: Can't unlock extension vault 'CredMan': The vault doesn't support the Unlock-SecretVault
function.
```

This example uses the command to unlock the `CredMan` vault. But the vault doesn't support unlocking
so the command has no effect. A warning is displayed informing that `CredMan` vault doesn't support
unlocking.

## PARAMETERS

### -Name

Name of the vault to unlock.

```yaml
Type: System.String
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
Type: System.Security.SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose,
-WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Object

## NOTES

## RELATED LINKS
