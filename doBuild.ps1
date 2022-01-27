# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
.DESCRIPTION
Implement build and packaging of the package and place the output $OutDirectory/$ModuleName
#>
function DoBuild
{
    Write-Verbose -Verbose -Message "Starting DoBuild with configuration: $BuildConfiguration, framework: $BuildFramework"

    # Module build out path
    $BuildOutPath = "${OutDirectory}/${ModuleName}"
    Write-Verbose -Verbose -Message "Module output file path: '$BuildOutPath'"

    # Module build source path
    $BuildSrcPath = "bin/${BuildConfiguration}/${BuildFramework}/publish"
    Write-Verbose -Verbose -Message "Module build source path: '$BuildSrcPath'"

    # Reference assembly source path
    $RefSrcPath = "bin/${BuildConfiguration}/${BuildFramework}/ref"

    # Copy psd1 file
    Write-Verbose -Verbose "Copy-Item ${SrcPath}/${ModuleName}.psd1 to $BuildOutPath"
    Copy-Item "${SrcPath}/${ModuleName}.psd1" "$BuildOutPath"

    # Copy format files here
    Write-Verbose -Verbose "Copy-Item ${SrcPath}/${ModuleName}.format.ps1xml to $BuildOutPath"
    Copy-Item "${SrcPath}/${ModuleName}.format.ps1xml" "$BuildOutPath"

    # Copy help
    Write-Verbose -Verbose -Message "Copying help files to '$BuildOutPath'"
    Copy-Item -Recurse "${HelpPath}/${Culture}" "$BuildOutPath"

    # Copy license
    Write-Verbose -Verbose -Message "Copying LICENSE file to '$BuildOutPath'"
    Copy-Item -Path "./LICENSE" -Dest "$BuildOutPath"

    # Copy notice
    Write-Verbose -Verbose -Message "Copying ThirdPartyNotices.txt to '$BuildOutPath'"
    Copy-Item -Path "./ThirdPartyNotices.txt" -Dest "$BuildOutPath"

    if ( Test-Path "${SrcPath}/code" ) {
        Write-Verbose -Verbose -Message "Building assembly and copying to '$BuildOutPath'"
        # build code and place it in the staging location
        Push-Location "${SrcPath}/code"
        try {
            # Get dotnet.exe command path.
            $dotnetCommand = Get-Command -Name 'dotnet' -ErrorAction Ignore

            # Check for dotnet for Windows (we only build on Windows platforms).
            if ($null -eq $dotnetCommand) {
                Write-Verbose -Verbose -Message "dotnet.exe cannot be found in current path. Looking in ProgramFiles path."
                $dotnetCommandPath = Join-Path -Path $env:ProgramFiles -ChildPath "dotnet\dotnet.exe"
                $dotnetCommand = Get-Command -Name $dotnetCommandPath -ErrorAction Ignore
                if ($null -eq $dotnetCommand) {
                    throw "Dotnet.exe cannot be found: $dotnetCommandPath is unavailable for build."
                }
            }

            Write-Verbose -Verbose -Message "dotnet.exe command found in path: $($dotnetCommand.Path)"

            # Check dotnet version
            Write-Verbose -Verbose -Message "DotNet version: $(& ($dotnetCommand) --version)"

            # Build source
            Write-Verbose -Verbose -Message "Building with configuration: $BuildConfiguration, framework: $BuildFramework"
            Write-Verbose -Verbose -Message "Building location: PSScriptRoot: $PSScriptRoot, PWD: $pwd"
            & ($dotnetCommand) publish --configuration $BuildConfiguration --framework $BuildFramework --output $BuildSrcPath

            # Dump build source output directory
            # $outResults = Get-ChildItem -Path "bin/${BuildConfiguration}/${BuildFramework}" -Recurse | Out-String
            # Write-Verbose -Verbose -Message $outResults

            # Place build results
            if (! (Test-Path -Path "$BuildSrcPath/${ModuleName}.dll"))
            {
                throw "Expected binary was not created: $BuildSrcPath/${ModuleName}.dll"
            }

            Write-Verbose -Verbose -Message "Copying implementation assembly $BuildSrcPath/${ModuleName}.dll to $BuildOutPath"
            Copy-Item "$BuildSrcPath/${ModuleName}.dll" -Dest "$BuildOutPath"
            
            if (Test-Path -Path "$BuildSrcPath/${ModuleName}.pdb")
            {
                Write-Verbose -Verbose -Message "Copying implementation pdb $BuildSrcPath/${ModuleName}.pdb to $BuildOutPath"
                Copy-Item -Path "$BuildSrcPath/${ModuleName}.pdb" -Dest "$BuildOutPath"
            }

            Write-Verbose -Verbose "$BuildSrcPath/System.Runtime.InteropServices.RuntimeInformation.dll to $BuildOutPath"
            Copy-Item -Path "$BuildSrcPath/System.Runtime.InteropServices.RuntimeInformation.dll" -Dest "$BuildOutPath"

            if (! (Test-Path -Path "$RefSrcPath/${ModuleName}.dll"))
            {
                # throw "Expected ref binary was not created: $RefSrcPath/${ModuleName}.dll"
                Write-Verbose -Verbose -Message "Cannot find reference assembly $RefSrcPath/${ModuleName}.dll"
                Write-Verbose -Verbose -Message "Copying implementation assembly as reference assembly $RefSrcPath/${ModuleName}.dll to $script:OutReferencePath"
                Copy-Item -Path "$BuildSrcPath/${ModuleName}.dll" -Dest $script:OutReferencePath
            }
            else
            {
                Write-Verbose -Verbose -Message "Copying reference assembly $RefSrcPath/${ModuleName}.dll to $script:OutReferencePath"
                Copy-Item -Path "$RefSrcPath/${ModuleName}.dll" -Dest $script:OutReferencePath
            }

            # Create nuget package for reference assembly based on Microsoft.PowerShell.SecretManagement.Library.nuspec file.
            dotnet pack --no-build --configuration $BuildConfiguration --no-restore

            # Copy ref assembly nuget package to out.
            $NuGetSrcPath = "bin/${BuildConfiguration}/Microsoft.PowerShell.SecretManagement.Library*.nupkg"
            if (!(Test-Path -Path $NuGetSrcPath))
            {
                Write-Verbose -Verbose -Message "Expected Nuget package was not created: $NuGetSrcPath"
            }
            else
            {
                Write-Verbose -Verbose -Message "Copying reference nuget package $NuGetSrcPath to $OutDirectory"
                Copy-Item -Path $NuGetSrcPath -Dest $OutDirectory
            }
        }
        catch {
            Write-Verbose -Verbose -Message "dotnet build failed with error: $_"
            Write-Error "dotnet build failed with error: $_"
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Verbose -Verbose -Message "No code to build in '${SrcPath}/code'"
    }

    ## Add build and packaging here
    Write-Verbose -Verbose -Message "Ending DoBuild"
}
