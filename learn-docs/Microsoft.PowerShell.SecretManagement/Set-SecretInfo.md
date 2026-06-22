---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/set-secretinfo?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Set-SecretInfo

## SYNOPSIS
Adds or replaces additional secret metadata to a secret currently stored in a vault.

## SYNTAX

### NameParameterSet (Default)

```
Set-SecretInfo [-Name] <String> [-Metadata] <Hashtable> [[-Vault] <String>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### InfoParameterSet

```
Set-SecretInfo [-Metadata] <Hashtable> -InputObject <SecretInformation>
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet adds additional secret metadata to an existing secret. Metadata support is an optional
feature for an extension vault. The command throws an error if a vault doesn't support secret
metadata. Metadata is a Hashtable object containing Name/Value pairs. The metadata is stored
unencrypted. You shouldn't store sensitive information in the metadata.

## EXAMPLES

### Example 1

```powershell
Set-SecretInfo -Name Secret1 -Vault Vault1 -Metadata @{
    Expiration = ([datetime]::new(2022, 5, 1))
}
Get-SecretInfo -Name Secret1 -Vault Vault1 |
    Select-Object Name,Metadata
```

```output
Name         Metadata
----         --------
Secret1 {[Expiration, 5/1/2022 12:00:00 AM]}
```

This example adds metadata to the `Secret1` secret stored in `Vault1` vault. `Get-SecretInfo`
retrieves the metadata for `Secret1` to show the added metadata.

### Example 2

```powershell
Set-SecretInfo -Name Secret2 -Vault Vault2 -Metadata @{
    Expiration = ([datetime]::new(2022, 5, 1))
}
```

```output
Set-SecretInfo: Can't set secret metadata Secret2. Vault Vault2 doesn't support secret metadata.
```

This example adds metadata to the `Secret2` secret stored in `Vault2` vault. However, `Vault2` does
not support metadata. The command fails and returns an error.

### Example 3

```powershell
Get-SecretInfo -Name Secret3 |
    Set-SecretInfo -Metadata @{ Created = (Get-Date) }
```

This example pipes a **SecretInformation** object to the `Set-SecretInfo` command and adds metadata
to the associated secret.

## PARAMETERS

### -InputObject

This parameter takes a **SecretInformation** object that defines the secret to be updated.

```yaml
Type: Microsoft.PowerShell.SecretManagement.SecretInformation
Parameter Sets: InfoParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Metadata

Specifies a **Hashtable** containing key-value pairs to associate with the secret in the vault. The
specified extension vault may not support secret metadata. If the vault doesn't support metadata,
the operation fails and returns an error. The values of any metadata in the hashtable must be one of
the following types:

- **string**
- **int**
- **DateTime**

Metadata isn't stored securely in a vault. Metadata shouldn't contain sensitive information.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: NameParameterSet, System.Collections.Hashtable
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Name

Specifies the name of the secret to add metadata to. Wildcard characters (`*`) aren't permitted.

```yaml
Type: System.String
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Vault

Specifies the name of the vault containing the secret to add or update the metadata for. Wildcard
characters (`*`) aren't permitted. By default, this cmdlet looks for the secret in the current
user's default vault.

```yaml
Type: System.String
Parameter Sets: NameParameterSet
Aliases:

Required: False
Position: 2
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

### System.Collections.Hashtable

## OUTPUTS

### None

## NOTES

## RELATED LINKS
