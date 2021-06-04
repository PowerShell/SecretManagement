---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Remove-Secret

## SYNOPSIS
Removes a secret from a specified registered extension vault.

## SYNTAX

### NameParameterSet
```
Remove-Secret [-Name] <String> [-Vault] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### InfoParameterSet
```
Remove-Secret [-InputObject] <SecretInformation> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will remove a secret by name from a registered extension vault.
Both the secret name and extension vault name must be provided.

## EXAMPLES

### Example 1
```powershell
PS C:\> Remove-Secret -Name secretTest -Vault CredMan
PS C:\> Get-Secret -Name secretTest -Vault CredMan
Get-Secret: The secret secretTest was not found.
```

This example runs the command to remove the secret 'secretTest' from the CredMan vault.
The 'Get-Secret' command is next run to verify the secret no longer exists in the vault.

### Example 2
```
PS C:\> Get-SecretInfo -Name Secret2 -Vault CredMan | Remove-Secret
PS C:\> Get-Secret -Name Secret2 -Vault CredMan
Get-Secret: The secret Secret2 was not found.
```

This example first obtains secret information for the 'Secret2' secret and pipes the results to this command.
Remove-Secret then removes the secret from the vault using the piped in secret information.

## PARAMETERS

### -InputObject
SecretInformation object that describes a vault secret.

```yaml
Type: SecretInformation
Parameter Sets: InfoParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Name
Name of the secret to remove.

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

### -Vault
Name of the vault from which the secret is to be removed.

```yaml
Type: String
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

### System.String
### Microsoft.PowerShell.SecretManagement.SecretInformation
## OUTPUTS

## NOTES

## RELATED LINKS
