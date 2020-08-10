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
Set-Secret [-Name] <String> [-SecureStringSecret] <SecureString> [[-Vault] <String>] [-NoClobber]
 [<CommonParameters>]
```

### ObjectParameterSet
```
Set-Secret [-Name] <String> [-Secret] <Object> [[-Vault] <String>] [-NoClobber] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet adds a secret value by name to SecretManagement.
If no vault name is specified, then the secret will be added to the default vault.
If an existing secret by the same name exists, it will be overwritten with the new value unless the 'NoClobber' parameter switch is used.
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
```powershell
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

## PARAMETERS

### -Name
Name of secret to add.

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

### -NoClobber
When used this parameter will cause an error if the secret name already exists.

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
Position: 1
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
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Vault
Optional name of vault to which the secret is added.
If omitted, the secret will be added to the default vault.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Object

### System.Security.SecureString

## OUTPUTS

## NOTES

## RELATED LINKS
