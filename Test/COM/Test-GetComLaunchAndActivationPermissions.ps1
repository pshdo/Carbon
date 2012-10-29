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

function Setup
{
    & (Join-Path $TestDir ..\..\Carbon\Import-Carbon.ps1 -Resolve)
}

function TearDown
{
    Remove-Module Carbon
}

function Test-ShouldGetComLaunchAndActivationPermissions
{
    $rules = Get-ComLaunchAndActivationPermissions -Default
    Assert-NotNull $rules
    Assert-True ($rules.Count -gt 1)
    $rules | ForEach-Object { 
        Assert-NotNull $_.IdentityReference
        Assert-NotNull $_.ComAccessRights
        Assert-NotNull $_.AccessControlType
        Assert-False $_.IsInherited
        Assert-Equal 'None' $_.InheritanceFlags
        Assert-Equal 'None' $_.PropagationFlags
     }
}

function Test-ShouldGetRuleForSpecificUser
{
    $rules = Get-ComLaunchAndActivationPermissions -Default
    Assert-GreaterThan $rules.Count 1
    $rule = Get-ComLaunchAndActivationPermissions -Default -Identity $rules[0].IdentityReference.Value
    Assert-NotNull $rule
    Assert-Equal $rule.IdentityReference $rules[0].IdentityReference
}

function Test-ShouldGetSecurityLimits
{
    $defaultRules = Get-ComLaunchAndActivationPermissions -Default
    Assert-NotNull $defaultRules
    
    $limitRules = Get-ComLaunchAndActivationPermissions -Limits
    Assert-NotNull $limitRules
    
    if( $defaultRules.Count -eq $limitRules.Count )
    {
        for( $idx = 0; $idx -lt $limitRules.Count; $idx++ )
        {
            Assert-NotEqual $defaultRules[$idx] $limitRules[$idx]
        }
    }    
}