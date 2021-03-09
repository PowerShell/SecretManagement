---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
online version:
schema: 2.0.0
---

# Set-Secret

## SYNOPSIS
Adds a secret to a SecretManagement registered vault.

## SYNTAX

### SecureStringParameterSet (Default)
```
Set-Secret [-Name] <String> -SecureStringSecret <SecureString> [[-Vault] <String>] [[-Metadata] <Hashtable>]
 [-NoClobber] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ObjectParameterSet
```
Set-Secret [-Name] <String> -Secret <Object> [[-Vault] <String>] [[-Metadata] <Hashtable>] [-NoClobber]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### SecretInfoParameterSet
```
Set-Secret -SecretInfo <SecretInformation> [-Vault] <String> [-NoClobber] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
This cmdlet adds a secret value by name to SecretManagement.
If no vault name is specified, then the secret will be added to the default vault.
If an existing secret by the same name exists, it will be overwritten with the new value unless the 'NoClobber' parameter switch is used.
Additional data can be included with the secret through the `-Metadata` parameter, if supported by the extension vault.
If the extension vault does not support metadata then an error will be generated and the operation will fail.
Metadata is not required to be stored securely, and should not contain sensitive information.  

The secret value must be one of five supported types:

- byte[]
- String
- SecureString
- PSCredential
- Hashtable

The default parameter set takes a SecureString object.
So if the command is run without specifying the secret value, the user will be safely prompted to enter a SecureString which cannot be seen on the console.

## EXAMPLES

### Example 1
```
PS C:\> Set-Secret -Name Secret1 -Secret "SecretValue"
PS C:\> Get-Secret -Name Secret1
System.Security.SecureString
```

This example adds a secret named 'Secret1' with a plain text value of 'SecretValue'.
Since no vault name was specified, the secret is added to the current default vault.
Next, the 'Get-Secret' command is run to verify the added secret.

### Example 2
```powershell
PS C:\> Set-Secret -Name Secret2 -Vault LocalStore

cmdlet Set-Secret at command pipeline position 1
Supply values for the following parameters:
SecureStringSecret: ***********

PS C:\> Get-Secret -Name Secret2
System.Security.SecureString
```

This example adds a secret named 'Secret2' to the LocalStore vault.
Since no secret value was provided, the user is prompted for a SecureString value.
The console hides the string value as it is typed.
Next, the 'Get-Secret' command is run to verify the secret was added.

### Example 3
```powershell
PS C:\> Set-Secret -Name TargetSecret -Secret $targetToken -Vault LocalStore -Metadata @{ Expiration = ([datetime]::new(2022, 5, 1)) }
PS C:\> Get-SecretInfo -Name TargetSecret | Select-Object Name,Metadata

Name         Metadata
----         --------
TargetSecret {[Expiration, 5/1/2022 12:00:00 AM]}
```

This example adds a secret named 'TargetSecret' to the LocalStore vault, along with extra metadata indicating the secret expiration date.
The metadata is retrieved using the `Get-SecretInfo` cmdlet.

### Example 4
```powershell
PS C:\> Set-Secret -Name PublishSecret -Secret $targetToken -Vault LocalStore2 -Metadata @{ Expiration = ([datetime]::new(2022, 5, 1)) }
Set-Secret: Cannot store secret PublishSecret. Vault LocalStore2 does not support secret metadata.
```

This example adds a secret named 'PublishSecret' to the LocalStore2 vault, along with extra metadata.
However, vault LocalStore2 does not support secret metadata and the operation fails with error.

## PARAMETERS

### -Metadata
Hashtable containing Name/Value pair that are stored in the vault.
The specified extension vault may not support secret metadata, in which case the operation will fail.
The metadata Name/Value value type must be one of the following:
- string
- int
- DateTime

```yaml
Type: Hashtable
Parameter Sets: SecureStringParameterSet, ObjectParameterSet
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
Name of secret for which the metadata is added

```yaml
Type: String
Parameter Sets: SecureStringParameterSet, ObjectParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoClobber
{{ Fill NoClobber Description }}

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

### -Secret
A secret value to be added.
The object type must be one of the supported types.

```yaml
Type: Object
Parameter Sets: ObjectParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -SecretInfo
A SecretInformation object describing a stored secret returned by `Get-SecretInfo`.
This allows moving secrets from one extension vault to another.

```yaml
Type: SecretInformation
Parameter Sets: SecretInfoParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -SecureStringSecret
A secret SecretString object to be added.

```yaml
Type: SecureString
Parameter Sets: SecureStringParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Vault
Optional name of vault to which the secret is added.
If omitted, the secret will be added to the default vault.

```yaml
Type: String
Parameter Sets: SecureStringParameterSet, ObjectParameterSet
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: SecretInfoParameterSet
Aliases:

Required: True
Position: 2
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

### System.Collections.Hashtable
## OUTPUTS

## NOTES

## RELATED LINKS
