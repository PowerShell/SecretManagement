---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Unregister-SecretVault

## SYNOPSIS
Un-registers an extension vault from SecretManagement for the current user.

## SYNTAX

### NameParameterSet
```
Unregister-SecretVault [-Name] <String[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### SecretVaultParameterSet
```
Unregister-SecretVault [-SecretVault] <SecretVaultInfo> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet un-registers the specified extension vault.
Once un-registered, the vault is no longer available to SecretManagement, for the current user.

## EXAMPLES

### Example 1
```
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True

PS C:\> Unregister-SecretVault LocalStore
PS C:\> Get-SecretVault

VaultName ModuleName                        IsDefaultVault
--------- ----------                        --------------
CredMan   Microsoft.PowerShell.CredManStore False

PS C:\> Get-Secret -Name Secret5
Get-Secret: The secret Secret5 was not found.

PS C:\> Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
PS C:\> Get-SecretVault

VaultName   ModuleName                        IsDefaultVault
---------   ----------                        --------------
CredMan     Microsoft.PowerShell.CredManStore False
SecretStore Microsoft.PowerShell.SecretStore  True

PS C:\> Get-Secret -Name Secret5
System.Security.SecureString
```

In this example, 'Get-SecretVault' command is run to see what vaults are registered for the current user.
Next, the 'LocalStore' vault is un-registered.
'Get-SecretVault' command is run again to verify the vault no longer appears in the registry.
An attempt is made to retrieve 'Secret5', but it is not found since its vault was un-registered.
The vault is re-registered, under a different name, and set to be the default vault.
'Get-SecretVault' is run again to verify the newly registered vault.
Finally, the 'Secret5' secret is retrieved successfully from the new default vault.

### Example 2
```
PS C:\> Get-SecretVault | Unregister-SecretVault
PS C:\> Get-SecretVault
PS C:\>
```

In this example, 'Get-SecretVault' output is piped to this 'Unregister-SecretVault' cmdlet to un-register all extension vaults for the current user.
Next, 'Get-SecretVault' is run again to show that no vaults are registered.

## PARAMETERS

### -Name
Name of the vault to un-register.

```yaml
Type: String[]
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: True
```

### -SecretVault
SecretVaultInfo object, returned by 'Get-SecretVault' cmdlet.
This can alternately be used to indicate a vault to be un-registered.

```yaml
Type: SecretVaultInfo
Parameter Sets: SecretVaultParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### Microsoft.PowerShell.SecretManagement.SecretVaultInfo
## OUTPUTS

## NOTES

## RELATED LINKS
