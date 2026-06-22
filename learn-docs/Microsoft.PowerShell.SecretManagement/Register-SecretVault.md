---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/register-secretvault?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Register-SecretVault

## SYNOPSIS
Registers a SecretManagement extension vault module for the current user.

## SYNTAX

```
Register-SecretVault [-ModuleName] <String> [[-Name] <String>] [-VaultParameters <Hashtable>]
 [-DefaultVault] [-AllowClobber] [-PassThru] [-Description <String>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

This cmdlet adds a **SecretManagement** extension vault to the current user's vault registry. An
extension vault is a PowerShell module that conforms to the required extension vault format. This
cmdlet verifies that the specified module meets conformance requirements before adding it to the
extension vault registry. Extension vaults are registered to the current user and don't affect
other user vault registrations.

The first vault registered with this cmdlet is automatically defined as the default vault even if
the **DefaultVault** parameter isn't specified.

## EXAMPLES

### Example 1

```powershell
Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Get-SecretVault
```

```output
VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True
```

This example registers a **Microsoft.PowerShell.SecretStore** extension vault for the current user.
It uses the **DefaultVault** parameter to make the registered vault the default vault for the user.
`Get-SecretVault` lists all registered vaults for the user, verifying the vault was registered and
set as the default vault.

### Example 2

```powershell
$parameters = @{
    Name = 'Azure'
    ModuleName = 'Az.KeyVault'
    VaultParameters = @{
        AZKVaultName = 'AzureKeyVault'
        SubscriptionId = (Get-AzContext).Subscription.Id
    }
    DefaultVault = $true
}
Register-SecretVault @parameters
Get-SecretVault
```

```Output
Name  ModuleName  IsDefaultVault
----  ----------  --------------
Azure Az.KeyVault True
```

This example registers an **Az.KeyVault** extension vault for the current user. The
[Az.KeyVault](https://www.powershellgallery.com/packages/Az.KeyVault/) module needs to be installed
on prior. For the **VaultParameters**:

- `AZKVaultName` specifies the name of the Key Vault on Azure
- `SubscriptionId` specifies the ID of the subscription where the Key Vault is created in

## PARAMETERS

### -AllowClobber

If specified, allows the cmdlet to overwrite an existing registered extension vault with the same
name.

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

### -DefaultVault

If specified, sets the new extension vault as the default vault for the current user.

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

### -Description

Describes the vault. This value is included in the vault registry information.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ModuleName

Specifies the name of the PowerShell module that implements the extension vault. Enter the name of a
module or the path to the module. If you specify a name, PowerShell searches for it in the known
module paths. If you specify a path, PowerShell searches that path for the module.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name

Specifies the name of the extension vault. If no name is specified, the module name is used as the
vault name.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru

Indicates that the cmdlet should return the **SecretVaultInfo** object for the successfully
registered extension vault. By default this cmdlet doesn't return any output.

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

### -VaultParameters

Specifies a **Hashtable** object containing optional key-value pairs used as parameters by the
extension vault. These parameters are optional. Consult the documentation of the vault extension
module to see what values are required.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
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

### None

## OUTPUTS

### None

## NOTES

## RELATED LINKS
