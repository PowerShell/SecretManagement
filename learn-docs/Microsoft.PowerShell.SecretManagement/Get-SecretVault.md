---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/get-secretvault?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Get-SecretVault

## SYNOPSIS
Finds and returns registered vault information.

## SYNTAX

```
Get-SecretVault [[-Name] <String[]>] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet finds and returns information about registered vaults. By default, it returns
information for every registered vault.

## EXAMPLES

### Example 1

```powershell
Get-SecretVault
```

```output
VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True
```

This example runs the command without any parameters to return information on all registered vaults.
The `LocalStore` vault is shown to be set as the default vault.

### Example 2

```powershell
Get-SecretVault -Name LocalStore | Format-List -Property *
```

```output
Name            : LocalStore
ModuleName      : Microsoft.PowerShell.SecretStore
ModulePath      : C:\Users\User01\Documents\PowerShell\Modules\Microsoft.PowerShell.SecretStore
Description     : Personal secrets for non-production use.
VaultParameters : {}
IsDefault       : True
```

This example shows additional information about the `LocalStore` vault.

## PARAMETERS

### -Name

Specifies the name of a vault. This cmdlet only gets information for vaults that have the specified
name. Enter a name or name pattern. Wildcard characters are permitted.

If the **Name** parameter isn't specified, this cmdlet returns the information for all registered
vaults.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: True
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose,
-WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### Microsoft.PowerShell.SecretManagement.SecretVaultInfo

## NOTES

## RELATED LINKS
