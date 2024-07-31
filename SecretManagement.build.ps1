# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

#Requires -Modules @{ ModuleName = "InvokeBuild"; ModuleVersion = "5.0.0" }

$ProjectName = "SecretManagement"
$FullModuleName = "Microsoft.PowerShell.SecretManagement"
$CSharpSource = Join-Path $PSScriptRoot src/code
$CSharpPublish = Join-Path $PSScriptRoot artifacts/publish/$FullModuleName/$($Configuration.ToLower())
$ModuleOut = Join-Path $PSScriptRoot module
$PackageOut = Join-Path $PSScriptRoot out
$HelpSource = Join-Path $PSScriptRoot help
$HelpOut = Join-Path $ModuleOut en-US

$CSharpArtifacts = @(
    "$FullModuleName.dll",
    "$FullModuleName.pdb",
    "$FullModuleName.xml",
    "System.Runtime.InteropServices.RuntimeInformation.dll")

$BaseArtifacts = @(
    "src/$FullModuleName.format.ps1xml",
    "README.md",
    "LICENSE",
    "ThirdPartyNotices.txt")

$ManifestPath = Join-Path $PSScriptRoot "src/$FullModuleName.psd1"

$HelpAboutTopics = @()

task FindDotNet -Before Clean, Build {
    Assert (Get-Command dotnet -ErrorAction SilentlyContinue) "The dotnet CLI was not found, please install it: https://aka.ms/dotnet-cli"
    $DotnetVersion = dotnet --version
    Assert ($?) "The required .NET SDK was not found, please install it: https://aka.ms/dotnet-cli"
    Write-Host "Using dotnet $DotnetVersion at path $((Get-Command dotnet).Source)" -ForegroundColor Green
}

task Clean {
    Remove-BuildItem ./artifacts, $ModuleOut, $PackageOut
    Invoke-BuildExec { dotnet clean $CSharpSource }

    Remove-BuildItem "$HelpOut/$FullModuleName.dll-Help.xml"
    foreach ($aboutTopic in $HelpAboutTopics) {
        Remove-BuildItem "$HelpSource/$aboutTopic.help.txt"
    }
}

task BuildDocs -If { Test-Path -LiteralPath $HelpSource } {
    New-ExternalHelp -Path $HelpSource -OutputPath $HelpOut
    foreach ($aboutTopic in $HelpAboutTopics) {
        New-ExternalHelp -Path "$HelpSource\$aboutTopic.md" -OutputPath $HelpOut
    }
}

task BuildModule {
    New-Item -ItemType Directory -Force $ModuleOut | Out-Null

    Invoke-BuildExec { dotnet publish $CSharpSource --configuration $Configuration }

    # Hard code building this in release config since we aren't actually developing it,
    # it's only for tests. The tests also hard code the path assuming release config.
    Invoke-BuildExec { dotnet publish $PSScriptRoot/ExtensionModules/CredManStore/src/code --configuration Release }

    $CSharpArtifacts | ForEach-Object {
        $item = Join-Path $CSharpPublish $_
        Copy-Item -Force -LiteralPath $item -Destination $ModuleOut
    }

    $BaseArtifacts | ForEach-Object {
        $itemToCopy = Join-Path $PSScriptRoot $_
        Copy-Item -Force -LiteralPath $itemToCopy -Destination $ModuleOut
    }

    $propsContent = Get-Content $PSScriptRoot/Directory.Build.props -Raw
    $props = [xml]$propsContent
    $moduleVersion = $props.Project.PropertyGroup.ModuleVersion
    $manifestContent = Get-Content -LiteralPath $ManifestPath -Raw
    $newManifestContent = $manifestContent -replace '{{ModuleVersion}}', $moduleVersion
    Set-Content -LiteralPath "$ModuleOut/$FullModuleName.psd1" -Encoding utf8 -Value $newManifestContent
}

task PackageModule {
    New-Item -ItemType Directory -Force $PackageOut | Out-Null

    try {
        Register-PSResourceRepository -Name $ProjectName -Uri $PackageOut -ErrorAction Stop
        $registerSuccessful = $true
        Publish-PSResource -Path $ModuleOut -Repository $ProjectName -Verbose
    } finally {
        Unregister-PSResourceRepository -Name $ProjectName
    }
}

# AKA Microsoft.PowerShell.SecretManagement.Library
task PackageLibrary -If { $Configuration -eq "Release" } {
    Invoke-BuildExec { dotnet pack $CSharpSource --no-build --configuration $Configuration --output $PackageOut }
}

task Test {
    Invoke-Pester -CI -Output Diagnostic
}

task Build BuildModule, BuildDocs

task Package PackageModule, PackageLibrary

task . Clean, Build
