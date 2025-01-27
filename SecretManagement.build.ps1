# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

#Requires -Modules @{ ModuleName = "InvokeBuild"; ModuleVersion = "5.0.0" }

task FindDotNet -Before Clean, Build {
    Assert (Get-Command dotnet -ErrorAction SilentlyContinue) "The dotnet CLI was not found, please install it: https://aka.ms/dotnet-cli"
    $DotnetVersion = dotnet --version
    Assert ($?) "The required .NET SDK was not found, please install it: https://aka.ms/dotnet-cli"
    Write-Host "Using dotnet $DotnetVersion at path $((Get-Command dotnet).Source)" -ForegroundColor Green
}

task Clean {
    Remove-BuildItem ./artifacts, ./module, ./out
    Invoke-BuildExec { dotnet clean ./src/code }
}

task BuildDocs -If { Test-Path -LiteralPath ./help } {
    New-ExternalHelp -Path ./help -OutputPath ./module/en-US
}

task BuildModule {
    New-Item -ItemType Directory -Force ./module | Out-Null

    Invoke-BuildExec { dotnet publish ./src/code -c $Configuration }

    # Hard code building this in release config since we aren't actually developing it,
    # it's only for tests. The tests also hard code the path assuming release config.
    Invoke-BuildExec { dotnet publish ./ExtensionModules/CredManStore/src/code -c Release }
    
    $FullModuleName = "Microsoft.PowerShell.SecretManagement"

    $CSharpArtifacts = @(
        "$FullModuleName.dll",
        "$FullModuleName.pdb",
        "$FullModuleName.xml",
        "System.Runtime.InteropServices.RuntimeInformation.dll")

    $CSharpArtifacts | ForEach-Object {
        $item = "./artifacts/publish/$FullModuleName/$($Configuration.ToLower())/$_"
        Copy-Item -Force -LiteralPath $item -Destination ./module
    }

    $BaseArtifacts = @(
        "src/$FullModuleName.format.ps1xml",
        "README.md",
        "LICENSE",
        "ThirdPartyNotices.txt")

    $BaseArtifacts | ForEach-Object {
        $itemToCopy = Join-Path $PSScriptRoot $_
        Copy-Item -Force -LiteralPath $itemToCopy -Destination ./module
    }

    [xml]$xml = Get-Content Directory.Build.props
    $moduleVersion = $xml.Project.PropertyGroup.ModuleVersion
    $manifestContent = Get-Content -LiteralPath "./src/$FullModuleName.psd1" -Raw
    $newManifestContent = $manifestContent -replace '{{ModuleVersion}}', $moduleVersion
    Set-Content -LiteralPath "./module/$FullModuleName.psd1" -Encoding utf8 -Value $newManifestContent
}

task PackageModule {
    New-Item -ItemType Directory -Force ./out | Out-Null

    try {
        Register-PSResourceRepository -Name SecretManagement -Uri ./out -ErrorAction Stop
        Publish-PSResource -Path ./module -Repository SecretManagement -Verbose
    } finally {
        Unregister-PSResourceRepository -Name SecretManagement
    }
}

# AKA Microsoft.PowerShell.SecretManagement.Library
task PackageLibrary -If { $Configuration -eq "Release" } {
    Invoke-BuildExec { dotnet pack ./src/code --no-build -c $Configuration -o ./out }
}

task Test {
    Invoke-Pester -CI
}

task Build BuildModule, BuildDocs

task Package PackageModule, PackageLibrary

task . Clean, Build
