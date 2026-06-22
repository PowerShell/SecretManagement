---
external help file: Microsoft.PowerShell.SecretManagement.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretManagement
ms.date: 05/23/2025
online version: https://learn.microsoft.com/powershell/module/microsoft.powershell.secretmanagement/test-secretvault?view=ps-modules&wt.mc_id=ps-gethelp
schema: 2.0.0
---

# Test-SecretVault

## SYNOPSIS
Runs an extension vault self test.

## SYNTAX

```
Test-SecretVault [[-Name] <String[]>] [<CommonParameters>]
```

## DESCRIPTION

This cmdlet runs an extension vault self-test, by running the internal vault `Test-SecretVault`
command. It returns `$true` if all tests succeeded, and `$false` otherwise. Information on failing
tests is written to the error stream as error records. For more information during the test run use
the **Verbose** parameter.

## EXAMPLES

### Example 1

```powershell
PS C:\> Test-SecretVault -Name CredMan -Verbose
VERBOSE: Invoking command Test-SecretVault on module Microsoft.PowerShell.CredManStore.Extension
VERBOSE: Vault CredMan succeeded validation test
True
```

This example runs the self-tests on the `CredMan` extension vault. All tests succeeded.

## PARAMETERS

### -Name

Specifies the name of one or more vaults to test. Enter a name or name pattern. Wildcard characters
(`*`) are permitted.

If the **Name** parameter isn't specified, this cmdlet runs the tests for all registered vaults.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: True
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose,
-WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Boolean

## NOTES

## RELATED LINKS
