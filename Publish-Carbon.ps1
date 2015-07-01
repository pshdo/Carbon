<#
.SYNOPSIS
Packages and publishes Carbon packages.
#>

# Copyright 2012 Aaron Jensen
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='All')]
    [Switch]
    $All,
    
    [Parameter(ParameterSetName='Some')]
    [Switch]
    $ZipPackage,

    [Parameter(ParameterSetName='Some')]
    [Switch]
    # Update the website.
    $Website,

    [Parameter(ParameterSetName='Some')]
    [Switch]
    # Commit any changes made by the publishing process.
    $Commit
)

#Requires -Version 4
Set-StrictMode -Version Latest

if( $PSCmdlet.ParameterSetName -eq 'Some' )
{
    $All = $false
}

& (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon\Import-Carbon.ps1' -Resolve)

$licenseFileName = 'LICENSE.txt'
$releaseNotesFileName = 'RELEASE NOTES.txt'
$releaseNotesPath = Join-Path -Path $PSScriptRoot -ChildPath $releaseNotesFileName -Resolve

$carbonModule = Get-Module -Name 'Carbon'
$version = $carbonModule.Version
Write-Verbose ('Publishing version {0}.' -f $version)

$versionReleaseNotes = $null
foreach( $line in (Get-Content -Path $releaseNotesPath) )
{
    if( $line -match '^# ' )
    {
        $versionReleaseNotes = $line
        break
    }
}

if( $versionReleaseNotes -notmatch [regex]::Escape($version.ToString()) )
{
    Write-Error ('Unable to publish Carbon. Latest version in release notes file ''{0}'' is not {1}. Please build Carbon at that version, run tests, then publish again.' -f $versionReleaseNotes,$Version)
    return
}

$badAssemblies = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon\bin') -Filter 'Carbon*.dll' |
                        Where-Object { 
                            -not ($_.VersionInfo.FileVersion.ToString().StartsWith($Version.ToString())) -or -not ($_.VersionInfo.ProductVersion.ToString().StartsWith($Version.ToString()))
                        } |
                        ForEach-Object {
                            ' * {0} (FileVersion: {1}; ProductVersion: {2})' -f $_.Name,$_.VersionInfo.FileVersion,$_.VersionInfo.ProductVersion
                        }
if( $badAssemblies )
{
    Write-Error ('Unable to publish Carbon. Versions of the following assemblies are not {0}. Please build Carbon at that version, run tests, then publish again.{1}{2}' -f $version,([Environment]::NewLine),($badAssemblies -join ([Environment]::NewLine)))
    return
}

$versionName = Get-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon\bin\Carbon.dll') |
                    Select-Object -ExpandProperty VersionInfo |
                    Select-Object -ExpandProperty ProductVersion

if( $All -or $Website )
{
    $helpDirPath = Join-Path $PSScriptRoot Website\help
    Get-ChildItem $helpDirPath *.html | Remove-Item 
        
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Out-Html.ps1' -Resolve) -OutputDir $helpDirPath        

    hg addremove $helpDirPath

}

if( $All -or $ZipPackage )
{
    $releaseNotesPath = Join-Path $PSScriptRoot $releaseNotesFileName -Resolve
    $newVersionHeader = "# {0} ({1})" -f $version,((Get-Date).ToString("d MMMM yyyy"))
    $releaseNotes = Get-Content -Path $releaseNotesPath |
                        ForEach-Object {
                            if( $_ -match '^# Next$' )
                            {
                                return $newVersionHeader
                            }
                            elseif( $_ -match '^# {0}\s*' -f [regex]::Escape($version.ToString()) )
                            {
                                return $newVersionHeader
                            }
                            return $_
                        }
    $releaseNotes | Set-Content -Path $releaseNotesPath

    $carbonZipFileName = "Carbon-{0}.zip" -f $versionName

    $aspNetClientPath = Join-Path -Path $PSScriptRoot -ChildPath 'Website\aspnet_client'
    if( (Test-Path -Path $aspNetClientPath -PathType Container) )
    {
        Remove-Item -Path $aspNetClientPath -Recurse
    }
        
    if( Test-Path $carbonZipFileName -PathType Leaf )
    {
        Remove-Item $carbonZipFileName
    }

    $tempDir = [IO.Path]::GetRandomFileName()
    $tempDir = Join-Path -Path $env:TEMP -ChildPath $tempDir

    New-Item -Path $tempDir -ItemType 'Directory' | Out-String | Write-Verbose

    try
    {
        foreach( $item in @( 'Carbon', 'Website', 'Examples', $licenseFileName, $releaseNotesFileName ) )
        {
            $sourcePath = Join-Path -Path $PSScriptRoot -ChildPath $item
            $extraFiles = hg st --unknown --ignored $sourcePath
            if( $extraFiles )
            {
                Write-Error ('Unable to package: there are unknown/ignored files in {0}:{1} {2}' -f $sourcePath,([Environment]::NewLine),($extraFiles -join ('{0} ' -f ([Environment]::NewLine))))
                return
            }

            if( (Test-Path -Path $sourcePath -PathType Container) )
            {
                robocopy $sourcePath (Join-Path -Path $tempDir -ChildPath $item) /MIR /XF *.orig /XF *.pdb | Write-Verbose
            }
            else
            {
                Copy-Item -Path $sourcePath -Destination $tempDir
            }
        }

        # Put another copy of the license file with the module.
        Copy-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath $licenseFileName) -Destination (Join-Path -Path $tempDir -ChildPath 'Carbon')

        Compress-Item -Path (Get-ChildItem -Path $tempDir) -OutFile (Join-Path -Path $PSScriptRoot -ChildPath $carbonZipFileName)
    }
    finally
    {
        Remove-Item -Recurse -Path $tempDir
    }
}

if( $All -or $Commit )
{
    if( $All )
    {   
        hg commit -m ("Releasing version {0}." -f $Version) --include $releaseNotesFileName --include .\Website --include Carbon\Carbon.psd1 --include Carbon\bin
        if( -not (hg tags | Where-Object { $_ -like "$version*" } ) )
        {
            hg tag $version
        }
    }
}