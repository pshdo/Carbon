
function Generate-Password
{
    <#
    .SYNOPSIS
    Creates hard password.

    .DESCRIPTION
    Creates hard to guess password from randomized chars. The chars are based on Ascii table and contains numbers,letters,mathematical chars and others.

    .EXAMPLE
    Generate-Password -maxValue 9

    #>
    Param
    (
        [parameter(Mandatory=$true)]
        [ValidateRange(8,99)]
        [Int]$maxValue
    ) 
    $newPass = '' 

    1..$maxValue | ForEach-Object { 
        $newPass += [char](Get-Random -Minimum 48 -Maximum 122) 
    }  
    return $newPass+"Za!" #returning password with template(which is must have to fulfill domain policies if they occur
}
Generate-Password -maxValue 9


