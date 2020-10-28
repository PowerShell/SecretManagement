---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Set-DefaultVault

## SYNOPSIS
Sets the provided vault name as the default vault for the current user.

## SYNTAX

### NameParameterSet (Default)
```
Set-DefaultVault [-Name] <string> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### SecretVaultParameterSet
```
Set-DefaultVault [-SecretVault] <SecretVaultInfo> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet updates the vault registry to indicate the provided vault name as the default vault.
Only one registered vault can be the default vault.
If this cmdlet is run without specifying the 'Name' parameter, then no registered vault is the default vault.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True

PS C:\> Set-DefaultVault -Name CredMan
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore True
LocalStore Microsoft.PowerShell.SecretStore  False

PS C:\> Set-DefaultVault
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  False
```

This cmdlet first runs 'Get-SecretVault' command to get all registered vault information, and shows that the 'LocalStore' is currently the default vault for the user.
Next, the 'Set-DefaultVault' command is run to make the 'CredMan' vault the default vault.
The 'Get-SecretVault' command is run a second time to verify 'CredMan' vault is now default, and 'LocalStore' vault is no longer default.
Finally, the 'Set-DefaultVault' command is run with no 'Name' parameter, to remove the default designation from any registered vault.
The 'Get-SecretVault' is run once again to verify there is no default vault.

## PARAMETERS

### -Name

```yaml
Type: String
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SecretVault

```yaml
Type: SecretVaultInfo
Parameter Sets: SecretVaultParameterSet
Aliases:

Required: True
Position: 0
Default value: None
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
