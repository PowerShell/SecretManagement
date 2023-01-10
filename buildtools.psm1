# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$ConfigurationFileName = 'package.config.json'
Import-Module -Name PowerShellGet -MinimumVersion 3.0.18

function Get-BuildConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $ConfigPath = '.'
    )

    $resolvedPath = Resolve-Path $ConfigPath

    if (Test-Path $resolvedPath -PathType Container) {
        $fileNamePath = Join-Path -Path $resolvedPath -ChildPath $ConfigurationFileName
    }
    else {
        $fileName = Split-Path -Path $resolvedPath -Leaf
        if ($fileName -ne $ConfigurationFileName) {
            throw "$ConfigurationFileName not found in provided pathname: $resolvedPath"
        }
        $fileNamePath = $resolvedPath
    }

    if (! (Test-Path -Path $fileNamePath -PathType Leaf)) {
        throw "$ConfigurationFileName not found at path: $resolvedPath"
    }

    $configObj = Get-Content -Path $fileNamePath | ConvertFrom-Json

    # Expand config paths to full paths
    $projectRoot = Split-Path $fileNamePath
    $configObj.SourcePath = Join-Path $projectRoot -ChildPath $configObj.SourcePath
    $configObj.TestPath = Join-Path $projectRoot -ChildPath $configObj.TestPath
    $configObj.HelpPath = Join-Path $projectRoot -ChildPath $configObj.HelpPath
    $configObj.BuildOutputPath = Join-Path $projectRoot -ChildPath $configObj.BuildOutputPath
    if ($configObj.SignedOutputPath) {
        $configObj.SignedOutputPath = Join-Path $projectRoot -ChildPath $configObj.SignedOutputPath
    }
    else {
        $configObj | Add-Member -MemberType NoteProperty -Name SignedOutputPath -Value (Join-Path $projectRoot -ChildPath 'signed')
    }

    return $configObj
}

function Invoke-Build {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ScriptBlock] $BuildScript
    )

    Write-Verbose -Verbose -Message "Invoking build script"

    $BuildScript.Invoke()

    Write-Verbose -Verbose -Message "Finished invoking build script"
}

function Publish-AsNuGetPackage
{
    [CmdletBinding()]
    param (
        [Switch] $Signed
    )

    Write-Verbose -Verbose -Message "Creating new local package repo"
    $localRepoName = 'packagebuild-local-repo'
    $localRepoLocation = Join-Path -Path ([System.io.path]::GetTempPath()) -ChildPath $localRepoName
    if (Test-Path -Path $localRepoLocation) {
        Remove-Item -Path $localRepoLocation -Recurse -Force -ErrorAction Ignore
    }
    $null = New-Item -Path $localRepoLocation -ItemType Directory -Force

    Write-Verbose -Verbose -Message "Registering local package repo: $localRepoName"
    Register-PSResourceRepository -Name $localRepoName -Uri $localRepoLocation -Trusted -Force

    Write-Verbose -Verbose -Message "Publishing package to local repo: $localRepoName"
    $config = Get-BuildConfiguration
    if (! $Signed.IsPresent) {
        $modulePath = Join-Path -Path $config.BuildOutputPath -ChildPath $config.ModuleName
    } else {
        $modulePath = Join-Path -Path $config.SignedOutputPath -ChildPath $config.ModuleName
    }
    Publish-PSResource -Path $modulePath -Repository $localRepoName -SkipDependenciesCheck -Confirm:$false -Verbose

    if ($env:TF_BUILD) {
        Write-Verbose -Verbose -Message "Pushing module nuget package artifact to AzDevOps"
        $artifactName = "nupkg"
        $artifactPath = (Get-ChildItem -Path $localRepoLocation -Filter "$($config.ModuleName)*.nupkg").FullName
        $artifactPath = Resolve-Path -Path $artifactPath
        Write-Host "##vso[artifact.upload containerfolder=$artifactName;artifactname=$artifactName;]$artifactPath"
    }
}

function Invoke-Tests {
    [CmdletBinding()]
    param (
       
    )

    # TODO: 


}
