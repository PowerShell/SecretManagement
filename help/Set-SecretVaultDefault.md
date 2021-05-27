---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Set-SecretVaultDefault

## SYNOPSIS
Sets the provided vault name as the default vault for the current user.

## SYNTAX

### NameParameterSet (Default)
```
Set-SecretVaultDefault [-Name] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### SecretVaultParameterSet
```
Set-SecretVaultDefault [-SecretVault] <SecretVaultInfo> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ClearParameterSet
```
Set-SecretVaultDefault [-ClearDefault] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet updates the vault registry to designate the provided vault name as the default vault.
Only one registered vault can be the default vault.
If this cmdlet is run without specifying the 'Name' parameter, then no registered vault is designated as the default vault.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True

PS C:\> Set-SecretVaultDefault -Name CredMan
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore True
LocalStore Microsoft.PowerShell.SecretStore  False

PS C:\> Set-SecretVaultDefault
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  False
```

This cmdlet first runs 'Get-SecretVault' command to get all registered vault information, and shows that the 'LocalStore' is currently the default vault for the user.
Next, the 'Set-SecretVaultDefault' command is run to make the 'CredMan' vault the default vault.
The 'Get-SecretVault' command is run a second time to verify 'CredMan' vault is now default, and 'LocalStore' vault is no longer default.
Finally, the 'Set-SecretVaultDefault' command is run with no 'Name' parameter, to remove the default designation from any registered vault.
The 'Get-SecretVault' is run once again to verify there is no default vault.

## PARAMETERS

### -ClearDefault
Makes no registered vault the default vault.

```yaml
Type: SwitchParameter
Parameter Sets: ClearParameterSet
Aliases:

Required: False
Position: 0
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
Name of registered vault to be made the default vault.

```yaml
Type: String
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -SecretVault
A SecretVaultInfo object that represents the registered vault to be made the default vault.

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

### None
## OUTPUTS

## NOTES

## RELATED LINKS
