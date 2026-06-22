---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/unregister-secretvault?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Unregister-SecretVault

## SYNOPSIS
Un-registers an extension vault from SecretManagement for the current user.

## SYNTAX

### NameParameterSet

```
Unregister-SecretVault [-Name] <String[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

### SecretVaultParameterSet

```
Unregister-SecretVault [-SecretVault] <SecretVaultInfo> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet un-registers the specified extension vault. Once un-registered, the vault is no longer
available to **SecretManagement** for the current user.

## EXAMPLES

### Example 1

```powershell
PS C:\> Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True

PS C:\> Unregister-SecretVault LocalStore
PS C:\> Get-SecretVault

VaultName ModuleName                        IsDefaultVault
--------- ----------                        --------------
CredMan   Microsoft.PowerShell.CredManStore False

PS C:\> Get-Secret -Name Secret5
Get-Secret: The secret Secret5 wasn't found.

PS C:\> Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
PS C:\> Get-SecretVault

VaultName   ModuleName                        IsDefaultVault
---------   ----------                        --------------
CredMan     Microsoft.PowerShell.CredManStore False
SecretStore Microsoft.PowerShell.SecretStore  True

PS C:\> Get-Secret -Name Secret5
System.Security.SecureString
```

The first command lists the registered vaults for the current user. The second command un-registers
the `LocalStore` vault. The third command verifies that the vault no longer appears in the registry.
The fourth command attempts to retrieve `Secret5`, but it's not found since its vault was
un-registered. The fifth command re-registers the vault under a different name and sets it as the
user's default vault. The sixth command verifies that the vault has been re-registered as
`SecretStore` and is the default vault. Finally, the last command retrieves `Secret5` from the
re-registered vault.

### Example 2

```powershell
PS C:\> Get-SecretVault | Unregister-SecretVault
PS C:\> Get-SecretVault

```

This example un-registers all extension vaults for the current user. The second command shows that
no vaults are registered.

This example un-registers all extension vaults for the current user. `Get-SecretVault` retrieves all
registered vaults for the current user and sends the result through the pipeline to
`Unregister-SecretVault`. `Get-SecretVault` shows that the secret no longer exists in the vault.

## PARAMETERS

### -Name

Specifies the name of the vault to un-register. Enter a name or name pattern. Wildcard characters
(`*`) are permitted.

```yaml
Type: System.String[]
Parameter Sets: NameParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: True
```

### -SecretVault

Specifies a **SecretVaultInfo** object representing the vault to un-register.

```yaml
Type: Microsoft.PowerShell.SecretManagement.SecretVaultInfo
Parameter Sets: SecretVaultParameterSet
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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

### Microsoft.PowerShell.SecretManagement.SecretVaultInfo

## OUTPUTS

### None

## NOTES

## RELATED LINKS
