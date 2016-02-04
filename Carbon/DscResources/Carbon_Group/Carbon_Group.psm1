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

& (Join-Path -Path $PSScriptRoot -ChildPath '..\Initialize-CarbonDscResource.ps1' -Resolve)

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$GroupName
	)

    Write-Debug ('GetScript - Group Name: {0}' -f $groupName)

    $groupObj = (Get-Group -Name $GroupName -ErrorAction Ignore)

    $Ensure = $null
    if ($groupObj)
    {
        $Ensure = 'Present'
    }
    else
    {
        $Ensure = 'Absent'
    }

    $returnValue = @{
		GroupName = $GroupName
		Ensure = $Ensure
		Description = $groupObj.Description
		Members = $groupObj.Members
	}

    Write-Output $returnValue
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$GroupName,

		[System.String]
		$Description,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.String[]]
		$Members
	)

    Write-Debug ('SetScript - Group Name: {0}' -f $groupName)

    if ($Ensure -eq 'Present')
    {
        if ($Members)
        {
            Write-Debug ('Ensure is ''{0}'', installing group {1}' -f $Ensure,$GroupName)
            Write-Debug ('Members to be added:')
            ($Members | Format-Table -AutoSize -Wrap | Out-String | Write-Debug)

            Install-Group -Name $GroupName -Description $Description -Member $Members
        }
        else
        {
            Write-Debug ('Ensure is ''{0}'', installing group {1}' -f $Ensure,$GroupName)
            Install-Group -Name $GroupName -Description $Description
        }
    }
    else
    {
        Write-Debug ('Removing group {0}' -f $GroupName)
        Uninstall-Group -Name $GroupName
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$GroupName,

		[System.String]
		$Description,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[System.String[]]
		$Members
	)

    Write-Debug ('TestScript - Group Name: {0}' -f $groupName)

    $result = Test-Group -Name $GroupName

    if (-not $Members)
    {
        Write-Debug ('Group [{0}] exists' -f $GroupName)
    }
    elseif($result -and $Members)
    {
        $rawMembers = (Get-Group -Name $GroupName).Members

        Write-Debug ('Current members of group {0}' -f $groupName)
        # needs to be in parens otherwise get 'Undefined DSC resource Write-Verbose. Use Import-DSCResource to import the resource'
        ($rawMembers | Select SamAccountName,ContextType,@{Name="Domain";Expression={($_.Context.Name)}} | Format-Table -AutoSize -Wrap | Out-String | Write-Debug)

        $result = $true
        foreach ($member in $Members)
        {
            try
            {
                Write-Debug ('User Resolution - Start:    {0}' -f $member)
                $secPrincipal = Resolve-Identity -Name $member -ErrorAction Stop
            }
            catch
            {
                Write-Warning -Message ('User Resolution - Failed: {0}' -f $PSItem.Exception.Message)
                continue
            }

            Write-Debug ('User Resolution - Resolved: {0}' -f $member)

            $isInGroup = $false
            foreach ($currentMember in $rawMembers)
            {
                Write-Debug ('Comparing - {0} ({1}) --> {2} ({3})' -f $secPrincipal,$secPrincipal.Sid,$currentMember,$currentMember.Sid)
                if ($secPrincipal.Sid -eq $currentMember.Sid)
                {
                    Write-Debug ('Comparing - Match found for user: {0}' -f $secPrincipal)
                    $isInGroup = $true
                    break
                }
            }

            if (-not $isInGroup)
            {
                Write-Verbose (' [{0}] User {1} not a member.' -f $groupName,$member)
                $result = $false
            }
        }

        if( $result )
        {
            Write-Verbose (' [{0}] All members present.' -f $groupName)
        }
    }

    # The above code assumes Ensure = Present. If it's Absent, then just switch the results around
    If ($Ensure -eq 'Absent')
    {
        if ($result -eq $true)
        {
            $result = $false
        }
        else
        {
            $result = $true
        }
    }

    return $result
}

Export-ModuleMember -Function *-TargetResource

