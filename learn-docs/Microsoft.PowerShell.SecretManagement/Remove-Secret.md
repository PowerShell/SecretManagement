---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/remove-secret?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Remove-Secret

## SYNOPSIS
Removes a secret from a specified registered extension vault.

## SYNTAX

### NameParameterSet (Default)

```
Remove-Secret [-Name] <String> [-Vault] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### InfoParameterSet

```
Remove-Secret [-InputObject] <SecretInformation> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Removes a secret by name from a registered extension vault. Both the secret name and extension vault
name must be provided.

## EXAMPLES

### Example 1

```powershell
Remove-Secret -Name secretTest -Vault CredMan
Get-Secret -Name secretTest -Vault CredMan
```

```output
Get-Secret: The secret secretTest wasn't found.
```

This example removes the `secretTest` secret from the `CredMan` vault. The `Get-Secret` command
verifies that the secret no longer exists in the vault.

### Example 2

```powershell
Get-SecretInfo -Name Secret2 -Vault CredMan | Remove-Secret
Get-Secret -Name Secret2 -Vault CredMan
```

```output
Get-Secret: The secret Secret2 wasn't found.
```

This example removes the `Secret2` secret from the `CredMan` vault. `Get-SecretInfo` retrieves the
information for the secret and sends the result through the pipeline to `Remove-Secret`.
`Get-Secret` verifies that the secret no longer exists in the vault.

## PARAMETERS

### -InputObject

Specifies a **SecretInformation** object that describes a vault secret.

```yaml
Type: Microsoft.PowerShell.SecretManagement.SecretInformation
Parameter Sets: InfoParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Name

Specifies the name of the secret to remove. Wildcard characters (`*`) aren't permitted.

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

### -Vault

Specifies the name of the vault to remove the secret from. Wildcard characters (`*`) aren't
permitted.

```yaml
Type: System.String
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
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

### System.String

### Microsoft.PowerShell.SecretManagement.SecretInformation

## OUTPUTS

### None

## NOTES

## RELATED LINKS
