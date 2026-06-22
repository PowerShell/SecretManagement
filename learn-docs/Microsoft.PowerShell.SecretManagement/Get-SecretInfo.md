---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/get-secretinfo?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Get-SecretInfo

## SYNOPSIS
Finds and returns metadata information about secrets in registered vaults.

## SYNTAX

```
Get-SecretInfo [[-Name] <String>] [[-Vault] <String>] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet finds and returns information about secrets in registered vaults. By default, it returns
information for every secret in all registered vaults.

## EXAMPLES

### Example 1

```powershell
Get-SecretInfo -Name *
```

```output
Name                    Type VaultName
----                    ---- ---------
Secret1               String LocalStore
Secret2            ByteArray LocalStore
Secret3         SecureString LocalStore
Secret4         PSCredential LocalStore
Secret5            Hashtable LocalStore
Secret6            ByteArray CredMan
```

This example specifies the **Name** parameter as a single wildcard (`*`) character to return
metadata for all stored secrets. There are two registered vaults, `LocalStore` and `CredMan`. There
are six **SecretInformation** objects returned from the two vaults.

The output objects every valid type a secret can be:

- **ByteArray**
- **Hashtable**
- **PSCredential**
- **SecureString**
- **String**

### Example 2

```powershell
Get-SecretInfo -Name SecretWithMetadata | Select-Object -ExpandProperty Metadata
```

```output
Key         Value
---         -----
Environment Development
Expiration  5/1/2022 12:00:00 AM
GroupNumber 7
```

This example retrieves the `SecretWithMetadata` secret and displays its metadata. The entries in the
hashtable show every valid type metadata values can be:

- **String**
- **DateTime**
- **Int**

## PARAMETERS

### -Name

Specifies the name of a secret. This cmdlet only gets metadata for secrets that have the specified
name. Enter a name or name pattern. Wildcard characters are permitted.

If the **Name** parameter isn't specified, this cmdlet returns the metadata for all stored secrets.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: True
```

### -Vault

Specifies the name of a vault to search for secret metadata. Wildcard characters aren't permitted.

If the **Vault** parameter isn't specified, this cmdlet searches for metadata in all registered
vaults.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
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

### Microsoft.PowerShell.SecretManagement.SecretInformation

## NOTES

## RELATED LINKS
