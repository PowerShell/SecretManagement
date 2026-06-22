---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/get-secret?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Get-Secret

## SYNOPSIS
Finds and returns a secret by name from registered vaults.

## SYNTAX

### NameParameterSet (Default)

```
Get-Secret [-Name] <String> [[-Vault] <String>] [-AsPlainText] [<CommonParameters>]
```

### InfoParameterSet

```
Get-Secret [-InputObject] <SecretInformation> [-AsPlainText] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet finds and returns the first secret that matches the provided name. If a vault name is
specified, only that vault is searched. Otherwise, it searches all vaults and returns the first
matching result. If the vault registry has a default vault, the cmdlet searches that vault before
any other registered vault. Secrets that are **String** or **SecureString** types are returned as
**SecureString** objects by default.

## EXAMPLES

### Example 1

```powershell
Get-Secret -Name Secret1 -Vault CredMan
Get-Secret -Name Secret1 -Vault CredMan -AsPlainText
```

```output
System.Security.SecureString
PlainTextSecretString
```

This example searches for a secret with the name `Secret1`, which is a **String** type secret. The
first command returns the secret as a **SecureString** object. The second command uses the
**AsPlainText** parameter to return the secret as a **String** object instead, displaying in the
console as plain text.

### Example 2

```powershell
Get-SecretInfo -Name Secret2 -Vault SecretStore |
    Get-Secret -AsPlainText
```

This example retrieves secret information for the secret named `Secret2` in the vault named
`SecretStore`. It then sends the result through the pipeline to `Get-Secret`, which searches for the
secret and returns it as plain text.

## PARAMETERS

### -AsPlainText

Specifies that a secret whose type is **String** or **SecureString** should be returned as a
**String** (in plain text) instead of a **SecureString**. If the secret being retrieved isn't a
**String** or **SecureString**, this parameter has no effect.

> [!CAUTION]
> To ensure security, you should avoid using plaintext strings whenever possible.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject

Specifies a **SecretInformation** object representing a vault secret instead of specifying the
**Name** and **Vault** parameters. You can get a **SecretInformation** object with the
`Get-SecretInfo` cmdlet.

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

Specifies the name of the secret to retrieve. Wildcard characters aren't permitted.

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

Specifies the name of the registered vault to retrieve the secret from. If no vault name is
specified, then all registered vaults are searched. If the vault registry has a default vault and
this parameter isn't specified, then the default vault is searched before the other registered
vaults.

```yaml
Type: System.String
Parameter Sets: NameParameterSet
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

### System.String

### Microsoft.PowerShell.SecretManagement.SecretInformation

## OUTPUTS

### System.Object

## NOTES

## RELATED LINKS
