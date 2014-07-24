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

function Start-Test
{
    & (Join-Path -Path $PSScriptRoot -ChildPath '..\..\Carbon\Import-Carbon.ps1' -Resolve)
}

function Stop-Test
{
}

function Test-ShouldGetAllUsers
{
    $users = Get-User
    Assert-NotNull $users
    Assert-GreaterThan $users.Length 0
    $users | ForEach-Object { Assert-is $_ ([DirectoryServices.AccountManagement.UserPrincipal]) }
}

function Test-ShouldGetOneUser
{
    Get-User |
        ForEach-Object { 
            $expectedUser = $_
            $user = Get-User -Username $expectedUser.SamAccountName
            Assert-Equal $expectedUser.Sid $user.Sid
        }
}

function Test-ShouldErrorIfUserNotFound
{
    $Error.Clear()
    $user = Get-User -Username 'fjksdjfkldj' -ErrorAction SilentlyContinue
    Assert-Null $user
    Assert-Equal 1 $Error.Count
    Assert-Like $Error[0].Exception.Message '*not found*'
}