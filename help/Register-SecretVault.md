---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Register-SecretVault

## SYNOPSIS
Registers a SecretManagement extension vault module for the current user.

## SYNTAX

```
Register-SecretVault [-Name] <String> [-ModuleName] <String> [-VaultParameters <Hashtable>] [-DefaultVault]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet adds a provided SecretManagement extension vault module to the current user vault registry.
An extension vault module is a PowerShell module that conforms to the required extension vault format.
This cmdlet will first verify that the provided module meets conformance requirements, and then add it to the extension vault registry.
Extension vaults are registered to the current user and do not affect other user vault registrations.

## EXAMPLES

### Example 1
```powershell
PS C:\> Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore  -DefaultVault
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True
```

This example registers the Microsoft.PowerShell.SecretStore extension vault module for the current user.
The 'Microsoft.PowerShell.SecretStore' is installed in a known PowerShell module path, so just the module name is needed.
It uses the 'DefaultVault' parameter switch to make it the default module for the user.
The 'Get-SecretVault' command is run next to list all registered vaults for the user, and verifies the vault was registered and set as the default vault.

## PARAMETERS

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DefaultVault
This parameter switch makes the new extension vault the default vault for the current user.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ModuleName
Name of the PowerShell module that implements the extension vault.
It can be a simple name, in which case PowerShell will search for it in its known module paths.
Alternatively, a pathname can be provided and PowerShell will look in the specific path for the module.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
Name of the extension vault to be registered.

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

### -VaultParameters
This takes a hashtable object that contains optional parameter name-value pairs needed by the extension vault.
These optional parameters are provided to the extension vault when invoked.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
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
