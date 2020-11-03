---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Get-SecretVault

## SYNOPSIS
Finds and returns registered vault information.

## SYNTAX

```
Get-SecretVault [[-Name] <string[]>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet finds and returns information of registered vaults.
It takes an array of vault name strings, which can contain wildcard characters.
If no 'Name' parameter is specified, all registered vault information is returned.
The registered vault information includes the vault name, vault implementing module name, and optional default parameters.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True
```

This example runs the command without any parameter arguments, and so returns information on all registered vaults.
The 'LocalStore' vault is shown to be set as the default vault.

## PARAMETERS

### -Name
This parameter takes a String argument, including wildcard characters.
It is used to filter the search results on vault names that match the provided name pattern.

```yaml
Type: string[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: True
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### Microsoft.PowerShell.SecretManagement.SecretVaultInfo

## NOTES

## RELATED LINKS
