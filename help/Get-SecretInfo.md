---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Get-SecretInfo

## SYNOPSIS
Finds and returns secret metadata information of one or more secrets.

## SYNTAX

```
Get-SecretInfo [[-Name] <String>] [[-Vault] <String>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet finds and returns secret metadata for secrets with names that match the provided 'Name'.
The 'Name' parameter argument can include wildcards for the search.
If no 'Name' parameter argument is provided then metadata for all secrets is returned.
The search is performed over all registered vaults, unless a specific vault name is specified.
Secret metadata consists of the secret name, secret type, and vault name.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretInfo -Name *

Name                    Type VaultName
----                    ---- ---------
Secret1               String LocalStore
Secret2            ByteArray LocalStore
Secret3         SecureString LocalStore
Secret4         PSCredential LocalStore
Secret5            Hashtable LocalStore
Secret6            ByteArray CredMan
```

This example runs the command with the 'Name' parameter argument being a single wildcard character.
So all metadata for all stored secrets is returned.
There are two registered vaults, LocalStore and CredMan.
There are six secrets metadata information returned over the two vaults.

## PARAMETERS

### -Name
This parameter takes a String argument, including wildcard characters.
It is used to filter the search results that match on secret names the provided name pattern.
If no 'Name' parameter argument is provided, then all stored secret metadata is returned.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Vault
Optional parameter which takes a String argument that specifies a single vault to search.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### Microsoft.PowerShell.SecretManagement.SecretInformation

## NOTES

## RELATED LINKS
