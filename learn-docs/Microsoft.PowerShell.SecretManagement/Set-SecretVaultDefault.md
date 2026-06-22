---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/set-secretvaultdefault?view=ps-modules&wt.mc_id=ps-gethelp
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

This cmdlet updates the vault registry to set the provided vault name as the default vault. Only one
registered vault can be the default vault.

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

PS C:\> Set-SecretVaultDefault -ClearDefault
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  False
```

This example shows how to set and unset the default vault for the current user. The first command
gets information about all registered vaults and shows that the `LocalStore` is the default vault
for the user. The second command makes the `CredMan` vault the default vault. The third command
shows that the `CredMan` vault is now default, and `LocalStore` vault is no longer default. The
fourth command uses the **ClearDefault** parameter to remove the default designation from any
registered vault. The last command shows that there is no default vault.

## PARAMETERS

### -ClearDefault

Sets the **IsDefault** property to `$false` for all registered vaults.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: ClearParameterSet
Aliases:

Required: False
Position: 0
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name

Specifies the name of a registered vault to set as the default vault. Wildcard characters (`*`) are
not permitted.

```yaml
Type: System.String
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -SecretVault

Specifies a **SecretVaultInfo** object representing the registered vault to set as the default
vault.

```yaml
Type: Microsoft.PowerShell.SecretManagement.SecretVaultInfo
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
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows what would happen if the cmdlet runs. The cmdlet isn't run.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
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

### None

## NOTES

## RELATED LINKS
