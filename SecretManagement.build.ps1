[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ProjectName = "SecretManagement"
$FullModuleName = 'Microsoft.PowerShell.SecretManagement'
$CSharpSource = Join-Path $PSScriptRoot src/code
$CSharpPublish = Join-Path $PSScriptRoot artifacts/publish
$ModuleOut = Join-Path $PSScriptRoot module
$PackageOut = Join-Path $PSScriptRoot out
$HelpSource = Join-Path $PSScriptRoot help
$HelpOut = Join-Path $ModuleOut en-US

$CSharpArtifacts = @(
    "$FullModuleName.dll",
    "$FullModuleName.pdb",
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
    Remove-BuildItem $ModuleOut, $PackageOut
    Invoke-BuildExec { dotnet clean $CSharpSource }

    Remove-BuildItem "$HelpOut/$FullModuleName.dll-Help.xml"
    foreach ($aboutTopic in $HelpAboutTopics) {
        Remove-BuildItem "$HelpSource/$aboutTopic.help.txt"
    }
}

task BuildDocs {
    if (-not (Test-Path -LiteralPath $HelpSource)) {
        return
    }

    New-ExternalHelp -Path $HelpSource -OutputPath $HelpOut | Out-Null
    foreach ($aboutTopic in $HelpAboutTopics) {
        New-ExternalHelp -Path "$HelpSource\$aboutTopic.md" -OutputPath $HelpOut | Out-Null
    }
}

task BuildModule {
    New-Item -ItemType Directory -Force $ModuleOut | Out-Null

    Invoke-BuildExec { dotnet publish $CSharpSource --configuration $Configuration --output $CSharpPublish }

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

    # New-ExternalHelp -Path docs/Microsoft.PowerShell.ConsoleGuiTools -OutputPath module/en-US -Force
}

task PackageModule {
    New-Item -ItemType Directory -Force $PackageOut | Out-Null

    try {
        Register-PSResourceRepository -Name $ProjectName -Uri $PackageOut -ErrorAction Stop
        $registerSuccessful = $true
        Publish-PSResource -Path $ModuleOut -Repository $ProjectName
    } finally {
        Unregister-PSResourceRepository -Name $ProjectName
    }
}

task PackageLibrary {
    Invoke-BuildExec { dotnet pack $CSharpSource --no-build --configuration $Configuration --no-restore --output $PackageOut }
}

task Build BuildModule, BuildDocs

task Package PackageModule, PackageLibrary

task . Clean, Build
