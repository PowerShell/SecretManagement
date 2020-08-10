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

```
Remove-Secret [-Name] <String> [-Vault] <String> [<CommonParameters>]
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

## PARAMETERS

### -Name
Name of the secret to remove.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Vault
Name of the vault from which the secret is to be removed.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String

## OUTPUTS

## NOTES

## RELATED LINKS
