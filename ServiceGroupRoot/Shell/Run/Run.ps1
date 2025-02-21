# ensure SAS variables were passed in
if ($env:SECRET_MANAGEMENT_MODULE -eq $null)
{
    Write-Verbose -Verbose "SECRET_MANAGEMENT_MODULE variable didn't get passed correctly"
    return 1
}

if ($env:SECRET_MANAGEMENT_VERSION -eq $null)
{
    Write-Verbose -Verbose "SECRET_MANAGEMENT_VERSION variable didn't get passed correctly"
    return 1
}

if ($env:DESTINATION_ACR_NAME -eq $null)
{
    Write-Verbose -Verbose "DESTINATION_ACR_NAME variable didn't get passed correctly"
    return 1
}

if ($env:DESTINATION_ACR_URI -eq $null)
{
    Write-Verbose -Verbose "DESTINATION_ACR_URI variable didn't get passed correctly"
    return 1
}

if ($env:MI_CLIENTID -eq $null)
{
    Write-Verbose -Verbose "MI_CLIENTID variable didn't get passed correctly"
    return 1
}


try {
    Write-Verbose -Verbose "SecretManagement: $env:SECRET_MANAGEMENT_MODULE"
    Write-Verbose -Verbose "Version: $env:SECRET_MANAGEMENT_VERSION"
    Write-Verbose -Verbose "acrname: $env:DESTINATION_ACR_NAME"
    Write-Verbose -Verbose "acruri: $env:DESTINATION_ACR_URI"
    Write-Verbose -Verbose "MI client Id: $env:MI_CLIENTID"

    $secretManagementFileName = "Microsoft.PowerShell.SecretManagement.$($env:SECRET_MANAGEMENT_VERSION).nupkg"

    Write-Verbose -Verbose "Download files"
    Invoke-WebRequest -Uri $env:SECRET_MANAGEMENT_MODULE -OutFile $secretManagementFileName

    $moduleExists = Test-Path $secretManagementFileName
    Write-Verbose -Verbose "Module $secretManagementFileName exists: $moduleExists"

    # Install PSResourceGet 1.1.0-preview2
    Write-Verbose "Download PSResourceGet version 1.1.0-preview2"
    Register-PSRepository -Name CFS -SourceLocation "https://pkgs.dev.azure.com/powershell/PowerShell/_packaging/powershell/nuget/v2" -InstallationPolicy Trusted
    Install-Module -Repository CFS -Name Microsoft.PowerShell.PSResourceGet -RequiredVersion '1.1.0' -Verbose
    Import-Module Microsoft.PowerShell.PSResourceGet
    Get-Module

    # Login to Azure CLI using Managed Identity
    Write-Verbose -Verbose "Login cli using managed identity"
    az login --identity --username $env:MI_CLIENTID

    # Register the target ACR as a PSResourceGet repository
    Write-Verbose -Verbose "Register ARC as a PSResourceGet reposirory"
    Register-PSResourceRepository -Uri $env:DESTINATION_ACR_URI -Name $env:DESTINATION_ACR_NAME -Trusted -Verbose

    Get-PSResourceRepository

    #Publish SecretManagement to ACR
    Write-Verbose -Verbose "Publish SecretManagement $secretManagementFileName to ACR $env:DESTINATION_ACR_NAME"
    $prefix = "public/psresource"
    Publish-PSResource -Repository $env:DESTINATION_ACR_NAME -NupkgPath $secretManagementFileName -ModulePrefix $prefix -Confirm:$false 
}
catch {

    $_.Exception | Format-List -Force

    return 1
}

return 0
