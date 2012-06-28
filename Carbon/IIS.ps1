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
Add-Type -AssemblyName "System.Web"

function Add-IisDefaultDocument
{
    <#
    .SYNOPSIS
    Adds a default document name to a website.
    
    .DESCRIPTION
    If you need a custom default document for your website, this function will add it.  The `FileName` argument should be a filename IIS should use for a default document, e.g. home.html.
    
    If the website already has `FileName` in its list of default documents, this function silently returns.
    
    .EXAMPLE
    Add-IisDefaultDocument -SiteName MySite -FileName home.html
    
    Adds `home.html` to the list of default documents for the MySite website.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the site where the default document should be added.
        $SiteName,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The default document to add
        $FileName
    )
    
    $xml = [xml] (Invoke-AppCmd list config `"$SiteName`" /section:defaultDocument )
    $docNode = $xml.SelectSingleNode( "/system.webServer/defaultDocument/files/add[@value = '$FileName']" )
    if( -not $docNode )
    {
        Invoke-AppCmd set config `"$SiteName`" /section:defaultDocument /+files.[value=`'$FileName`'] /commit:apphost
    }
}

function Get-IisHttpRedirect
{
    <#
    .SYNOPSIS
    Gets the HTTP redirect settings for a website or virtual directory/application under a website.
    
    .DESCRIPTION
    The settings are returned as a hashtable with the following properties:
    
     * Enabled - `True` if the redirect is enabled, `False` otherwise.
     * Destination - The URL where requests are directed to.
     * StatusCode - The HTTP status code sent to the browser for the redirect.
     * ExactDescription - `True` if redirects are to an exact destination, not relative to the destination.  Whatever that means.
     * ChildOnly - `True` if redirects are only to content in the destination directory (not subdirectories).
     
    .EXAMPLE
    Get-IisHttpRedirect -SiteName ExampleWebsite 
    
    Gets the redirect settings for ExampleWebsite.
    
    .EXAMPLE
    Get-IisHttpRedirect -SiteName ExampleWebsite -Path MyVirtualDirectory
    
    Gets the redirect settings for the MyVirtualDirectory virtual directory under ExampleWebsite.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The site's whose HTTP redirect settings will be retrieved.
        $SiteName,
        
        [string]
        # The optional path to a sub-directory under `SiteName` whose settings to return.
        $Path = ''
    )
    
    $settingsDoc = [xml] (Invoke-AppCmd list config "$SiteName/$Path" /section:httpRedirect)
    $settings = @{ }
    $httpRedirectElement = $settingsDoc['system.webServer'].httpRedirect
    $settings.Enabled = ($httpRedirectElement.enabled -eq 'true')
    $settings.Destination = $httpRedirectElement.destination
    $settings.StatusCode= $httpRedirectElement.httpResponseStatus
    $settings.ExactDestination = ($httpRedirectElement.exactDestination -eq 'true')
    $settings.ChildOnly = ($httpRedirectElement.childOnly -eq 'true')
    return $settings
}

function Get-IisVersion
{
    <#
    .SYNOPSIS
    Gets the version of IIS.
    
    .DESCRIPTION
    Reads the version of IIS from the registry, and returns it as a `Major.Minor` formatted string.
    
    .EXAMPLE
    Get-IisVersion
    
    Returns `7.0` on Windows 2008, and `7.5` on Windows 7 and Windows 2008 R2.
    #>
    [CmdletBinding()]
    param(
    )
    $props = Get-ItemProperty hklm:\Software\Microsoft\InetStp
    return $props.MajorVersion.ToString() + "." + $props.MinorVersion.ToString()
}

function Get-IisWebsite
{
    <#
    .SYNOPSIS
    Gets details about a website.
    
    .DESCRIPTION
    Returns an object containing the name, ID, bindings, and state of a website:
    
     * Bindings - An array of objects for each of the website's bindings.  Each object contains:
      * Protocol - The protocol of the binding, e.g. http, https.
      * IPAddress - The IP address the site is listening to, or * for all IP addresses.
      * Port - The port the site is listening on.
     * Name - The site's name.
     * ID - The site's ID.
     * State - The site's state, e.g. started, stopped, etc.
     
     .EXAMPLE
     Get-IisWebsite -SiteName 'WebsiteName'
     
     Returns the details for the site named `WebsiteName`.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the site to get.
        $SiteName
    )
    
    if( -not (Test-IisWebsiteExists -Name $SiteName) )
    {
        return $null
    }
    $siteXml = [xml] (Invoke-AppCmd list site $SiteName -xml)
    $siteXml = $siteXml.appcmd.SITE
    
    $site = @{ }
    
    $bindingsRaw = $siteXml.bindings -split ','
    $bindings = @()
    foreach( $bindingRaw in $bindingsRaw )
    {
        if( $bindingRaw -notmatch '^(https?)/([^:]*):([^:]*)(:(.*))?$' )
        {
            Write-Error "Unable to parse binding '$bindingRaw' for website '$SiteName'."
            continue
        }
        $binding = @{
                        Protocol = $matches[1];
                        IPAddress = $matches[2];
                        Port = $matches[3];
                    }
        $binding.HostName = ''
        if( $matches.Count -ge 5 )
        {
            $binding.HostName = $matches[5]
        }
        
        $bindings += New-Object PsObject -Property $binding
    }
    $site.Bindings = $bindings
    $site.Name = $siteXml.'SITE.NAME'
    $site.ID = $siteXml.'SITE.ID'
    $site.State = $siteXml.state
    return New-Object PsObject -Property $site
}

function Install-IisApplication
{
    <#
    .SYNOPSIS
    Creates a new application under a website.
    
    .DESCRIPTION
    Creates a new application at `Name` under website `SiteName` running the code found on the file system under `Path`, i.e. if SiteName is is `example.com`, the application is accessible at `example.com/Name`.  If an application already exists at that path, it is removed first.  The application can run under a custom application pool using the optional `AppPoolName` parameter.  If no app pool is specified, the application runs under the same app pool as the website it runs under.
    
    .EXAMPLE
    Install-IisApplication -SiteName Peanuts -Name CharlieBrown -Path C:\Path\To\CharlieBrown -AppPoolName CharlieBrownPool
    
    Creates an application at `Peanuts/CharlieBrown` which runs from `Path/To/CharlieBrown`.  The application runs under the `CharlieBrownPool`.
    
    .EXAMPLE
    Install-IisApplication -SiteName Peanuts -Name Snoopy -Path C:\Path\To\Snoopy
    
    Create an application at Peanuts/Snoopy, which runs from C:\Path\To\Snoopy.  It uses the same application as the Peanuts website.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The site where the application should be created.
        $SiteName,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the application.
        $Name,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the application.
        $Path,
        
        [string]
        # The app pool for the application.
        $AppPoolName
    )
    
    $appID = """$SiteName/$Name"""
    $output = Invoke-AppCmd list app $appID
    if( $output -like "*$appID*" )
    {
        Invoke-AppCmd delete app $appID
    }
    
    if( -not (Test-Path $Path -PathType Container) )
    {
        $null = New-Item $Path -ItemType Directory
    }
    
    Invoke-AppCmd add app /site.name:"$SiteName" /path:/$Name /physicalPath:"$Path"
    
    if( $AppPoolName )
    {
        Invoke-AppCmd set app /app.name:"$SiteName/$Name" /applicationPool:`"$AppPoolName`"
    }
}


function Install-IisAppPool
{
    <#
    .SYNOPSIS
    Creates a new app pool.
    
    .DESCRIPTION
    You can control which version of .NET is used to run an app pool with the `ManagedRuntimeVersion` parameter: versions `v1.0`, `v1.1`, `v2.0`, and `v4.0` are supported.

    To run an application pool using the classic pipeline mode, set the `ClassicPipelineMode` switch.

    To run an app pool using the 32-bit version of the .NET framework, set the `Enable32BitApps` switch.

    An app pool can run as several built-in service accounts, by passing one of them as the value of the `ServiceAccount` parameter: `NetworkService`, `LocalService`, `LocalSystem`, and `ApplicationPoolIdentity`.  Specifying `ApplicationPoolIdentity` causes IIS to create and use a custom local account with the name of the app pool.  See [Application Pool Identities](http://learn.iis.net/page.aspx/624/application-pool-identities/) for more information.

    To run the app pool as a specific user, pass the username and password for the account to the `Username` and `Password` parameters, respectively.

    If an existing app pool exists with name `Name`, it's settings are modified.  The app pool isn't deleted.  (You can't delete an app pool if there are any websites using it, that's why.)

    By default, this function will create an application pool running the latest version of .NET, with an integrated pipeline, as the NetworkService account.

    .EXAMPLE
    Install-IisAppPool -Name Cyberdyne -ServiceAccount NetworkService

    Creates a new Cyberdyne application pool, running as NetworkService, using .NET 4.0 and an integrated pipeline.  If the Cyberdyne app pool already exists, it is modified to run as NetworkService, to use .NET 4.0 and to use an integrated pipeline.

    .EXAMPLE
    Install-IisAppPool -Name Cyberdyne -ServiceAccount NetworkService -Enable32BitApps -ClassicPipelineMode

    Creates or sets the Cyberdyne app pool to run as NetworkService, in 32-bit mode (i.e. 32-bit applications are enabled), using the classic IIS request pipeline.

    .EXAMPLE
    Install-IisAppPool -Name Cyberdyne -Username 'PEANUTS\charliebrown' -Password '5noopyrulez'

    Creates or sets the Cyberdyne app pool to run as the `PEANUTS\charliebrown` domain account, under .NET 4.0, with an integrated pipeline.
    #>
    [CmdletBinding(DefaultParameterSetName='AsServiceAccount')]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The app pool's name.
        $Name,
        
        [string]
        [ValidateSet('v1.0','v1.1','v2.0','v4.0')]
        # The managed .NET runtime version to use.  Default is 'v4.0'.  Valid values are `v1.0`, `v1.1`, `v2.0`, or `v4.0`.
        $ManagedRuntimeVersion = 'v4.0',
        
        [int]
        [ValidateScript({$_ -gt 0})]
        #Idle Timeout value in minutes. Default is 0.
        $IdleTimeout = 0,
        
        [Switch]
        # Use the classic pipeline mode, i.e. don't use an integrated pipeline.
        $ClassicPipelineMode,
        
        [Switch]
        # Enable 32-bit applications.
        $Enable32BitApps,
        
        [Parameter(ParameterSetName='AsServiceAccount')]
        [string]
        [ValidateSet('NetworkService','LocalService','LocalSystem','ApplicationPoolIdentity')]
        # Run the app pool under the given local service account.  Valid values are `NetworkService`, `LocalService`, `LocalSystem`, and `ApplicationPoolIdentity`.  Specifying `ApplicationPoolIdentity` causes IIS to create a custom local user account for the app pool's identity.
        $ServiceAccount,
        
        [Parameter(ParameterSetName='AsSpecificUser',Mandatory=$true)]
        [string]
        # Runs the app pool under a specific user account.
        $UserName,
        
        [Parameter(ParameterSetName='AsSpecificUser',Mandatory=$true)]
        [string]
        # The password for the user account.  Can be a string or a SecureString.
        $Password
    )
    
    if( -not (Test-IisAppPoolExists -Name $Name) )
    {
        Invoke-AppCmd add apppool /name:`"$Name`" /commit:apphost
    }
    
    $pipelineMode = 'Integrated'
    if( $ClassicPipelineMode )
    {
        $pipelineMode = 'Classic'
    }
    
    Invoke-AppCmd set apppool `"$Name`" /managedRuntimeVersion:$ManagedRuntimeVersion /managedPipelineMode:$pipelineMode
    
    Invoke-AppCmd set config /section:applicationPools /[name=`'$Name`'].processModel.idleTimeout:"$(New-TimeSpan -minutes $IdleTimeout)"
    
    if( $Enable32BitApps )
    {
        Invoke-AppCmd set config /section:applicationPools /[name=`'$name`'].enable32BitAppOnWin64:true
    }
    
    if( $pscmdlet.ParameterSetName -eq 'AsServiceAccount' )
    {
        if( $ServiceAccount )
        {
            Invoke-AppCmd set config /section:applicationPools /[name=`'$Name`'].processModel.identityType:$ServiceAccount
        }
    }
    elseif( $pscmdlet.ParameterSetName -eq 'AsSpecificUser' )
    {
        if( $Password -is [Security.SecureString] )
        {
            $Password = Convert-SecureStringToString $Password
        }
        Invoke-AppCmd set config /section:applicationPools /[name=`'$Name`'].processModel.identityType:SpecificUser `
                                                           /[name=`'$Name`'].processModel.userName:$UserName `
                                                           /[name=`'$Name`'].processModel.password:$Password
    }
}

function Install-IisVirtualDirectory
{
    <#
    .SYNOPSIS
    Installs a virtual directory.

    .DESCRIPTION
    This function creates a virtual directory under website `SiteName` at `/Name`, serving files out of `Path`.  If a virtual directory called `Name` already exists, it is deleted first, and a new virtual directory is created.

    .EXAMPLE
    Install-IisVirtualDirectory -SiteName 'Peanuts' -Name 'DogHouse' -Path C:\Peanuts\Doghouse

    Creates a /DogHouse virtual directory, which serves files from the C:\Peanuts\Doghouse directory.  If the Peanuts website responds to hostname `peanuts.com`, the virtual directory is accessible at `peanuts.com/DogHouse`.

    .EXAMPLE
    Install-IisVirtualDirectory -SiteName 'Peanuts' -Name 'Brown/Snoopy/DogHouse' -Path C:\Peanuts\DogHouse

    Creates a DogHouse virtual directory under the `Peanuts` website at `/Brown/Snoopy/DogHouse` serving files out of the `C:\Peanuts\DogHouse` directory.  If the Peanuts website responds to hostname `peanuts.com`, the virtual directory is accessible at `peanuts.com/Brown/Snoopy/DogHouse`.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The site where the virtual directory should be created.
        $SiteName,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the virtual directory.  This can contain multiple directory segments for virtual directories not at the root of the website, e.g. First/Second/VirtualDirectory.
        $Name,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The file system path to the virtual directory.
        $Path
    )
    
    $vdirID = """$SiteName/$Name"""
    $output = Invoke-AppCmd list vdir $vdirID
    if( $output -like "*$vdirID*" )
    {
        Invoke-AppCmd delete vdir $vdirID
    }
    
    Invoke-AppCmd add vdir /app.name:"$SiteName/" / /path:/$Name /physicalPath:"$Path"       
}

function Install-IisWebsite
{
    <# 
    .SYNOPSIS
    Installs a website.

    .DESCRIPTION
    Installs a website named `Name`, serving files out of the file system from `Path`.  If no app pool name is given (via the `AppPoolName` parameter), IIS will pick one for you, usually the `DefaultAppPool`.  If a site with name `Name` already exists, it is deleted, and a new site is created.

    By default, the site listens on all IP addresses on port 80.  Set custom bindings with the `Bindings` argument.  Multiple bindings are allowed.  Each binding must be in this format (in BNF):

        <PROTOCOL> '/' <IP_ADDRESS> ':' <PORT> [ ':' <HOSTNAME> ]

     * `PROTOCOL` is one of `http` or `https`.
     * `IP_ADDRESS` is a literal IP address, or `*` for all of the computer's IP addresses.  This function does not validate if `IPADDRESS` is actually in use on the computer.
     * `PORT` is the port to listen on.
     * `HOSTNAME` is the website's hostname, for name-based hosting.  If no hostname is being used, leave off the last `: HOSTNAME` part.

    Valid bindings are:

     * http/*:80
     * https/10.2.3.4:443
     * http/*:80:example.com

    .EXAMPLE
    Install-IisWebsite -Name 'Peanuts' -Path C:\Peanuts.com

    Creates a website named `Peanuts` serving files out of the `C:\Peanuts.com` directory.  The website listens on all the computer's IP addresses on port 80.

    .EXAMPLE
    Install-IisWebsite -Name 'Peanuts' -Path C:\Peanuts.com -Bindings 'http/*:80:peanuts.com'

    Creates a website named `Peanuts` which uses name-based hosting to respond to all requests to any of the machine's IP addresses for the `peanuts.com` domain.

    .EXAMPLE
    Install-IisWebsite -Name 'Peanuts' -Path C:\Peanuts.com -AppPoolName 'PeanutsAppPool'

    Creates a website named `Peanuts` that runs under the `PeanutsAppPool` app pool
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$true)]
        [string]
        # The name of the website
        $Name,
        
        [Parameter(Position=1,Mandatory=$true)]
        [string]
        # The path to the website
        $Path,
        
        [Parameter(Position=2)]
        [string[]]
        # The site's network bindings.  Default is http/*:80.  Bindings should be specified in protocol/IPAddress:Port:Hostname format.  
        #
        #  * Protocol should be http or https. 
        #  * IPAddress can be a literal IP address or `*`, which means all of the computer's IP addresses.  This function does not validate if `IPAddress` is actually in use on this computer.
        #  * Leave hostname blank for non-named websites.
        $Bindings = @('http/*:80'),
        
        [string]
        # The name of the app pool under which the website runs.  The app pool must exist.  If not provided, IIS picks one for you.  No whammy, no whammy!
        $AppPoolName
        
    )
    
    if( Test-IisWebsiteExists -Name $Name )
    {
        Remove-IisWebsite -Name $Name
    }
    
    if( -not (Test-Path $Path -PathType Container) )
    {
        $null = New-Item $Path -ItemType Directory -Force
    }
    
    $bindingsArg = $Bindings -join ','
    Invoke-AppCmd add site /name:"$Name" /physicalPath:"$Path" /bindings:$bindingsArg
    
    if( $AppPoolName )
    {
        Invoke-AppCmd set site /site.name:"$Name" /[path=`'/`'].applicationPool:`"$AppPoolName`"
    }
    
    # Make sure anonymous authentication uses the application pool identity
    Invoke-AppCmd set config `"$Name`" /section:anonymousAuthentication /userName: /commit:apphost

    # Now, wait until site is actually running
    $tries = 0
    do
    {
        $website = Get-IisWebsite -SiteName $Name
        $tries += 1
        if($website.State -ne 'Unknown')
        {
            break
        }
        else
        {
            Start-Sleep -Milliseconds 100
        }
    }
    while( $tries -lt 100 )
}

function Invoke-AppCmd
{
    <#
    .SYNOPSIS
    Invokes appcmd.exe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        # The arguments to pass to appcmd.
        $AppCmdArgs
    )
    
    Write-Verbose ($AppCmdArgs -join " ")
    & (Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe') $AppCmdArgs
    if( $LastExitCode -ne 0 )
    {
        Write-Error "``AppCmd $($AppCmdArgs)`` exited with code $LastExitCode."
    }
}

function Remove-IisWebsite
{
    <#
    .SYNOPSIS
    Removes a website
    .EXAMPLE
    Remove-IisWebsite -Name 'MyWebsite'
    Removes MyWebsite
    .EXAMPLE
    Remove-IisWebsite 'MyWebsite'
    Removes MyWebsite
    .EXAMPLE
    Remove-IisWebsite 1
    Removes the website whose ID is 1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$true)]
        [string]
        # The name or ID of the website to remove.
        $Name
    )
    
    if( Test-IisWebsiteExists -Name $Name )
    {
        Invoke-AppCmd delete site `"$Name`"
    }
}

function Set-IisAnonymousAuthentication
{
    <#
    .SYNOPSIS
    Enables or disables anonymous authentication for all or part of a website.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        # The site where anonymous authentication should be set.
        $SiteName,
        
        [Parameter()]
        # The optional path where anonymous authentication should be set.
        $Path = '',
        
        [Switch]
        # Disable anonymous authentication.  Otherwise, it is enabled.
        $Disabled
    )
    
    $enabledArg = 'true'
    if( $Disabled )
    {
        $enabledArg = 'false'
    }
    
    if( $pscmdlet.ShouldProcess( "$SiteName/$Path", "set anonymous authentication" ) )
    {
        Invoke-AppCmd set config "$SiteName/$Path" '-section:anonymousAuthentication' /enabled:$enabledArg /username: /commit:apphost
    }
}

function Set-IisBasicAuthentication
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        # The site where basic authentication should be set.
        $SiteName,
        
        [Parameter()]
        # The optional path where basic authentication should be set.
        $Path = '',
        
        [Switch]
        # Disable basic authentication.  Otherwise, it is enabled.
        $Disabled
    )
    
    $enabledArg = 'true'
    if( $Disabled )
    {
        $enabledArg = 'false'
    }
    
    if( $pscmdlet.ShouldProcess( "$SiteName/$Path", "set basic authentication" ) )
    {
        Invoke-AppCmd set config "$SiteName/$Path" '-section:basicAuthentication' /enabled:$enabledArg /commit:apphost
    }
}

function Set-IisDirectoryBrowsing
{
    <#
    .SYNOPSIS
    Turns on directory browsing under a virtual directory.
    #>
    [CmdletBinding()]
    param(
        [string]
        # The name of the site where the virtual directory is located.
        $SiteName,
        
        [string]
        # The directory where directory browsing should be enabled.
        $Directory
    )
    
    $location = "$SiteName$Directory"
    if( $Directory -notlike '/*' )
    {
        $location = "$SiteName/$Directory"
    }
    
    Write-Verbose "Enabling directory browsing at location '$location'."
    Invoke-AppCmd set config `"$location`" /section:directoryBrowse /enabled:true /commit:apphost
}

function Set-IisHttpRedirect
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        # The site where the redirection should be setup.
        $SiteName,
        
        [Parameter()]
        # The optional path where redirection should be setup.
        $Path = '',
        
        [Parameter(Mandatory=$true)]
        [string]
        # The destination to redirect to.
        $Destination,
        
        [ValidateSet('Found','Permanent','Temporary')]
        [string]
        # The HTTP status code to use.
        $StatusCode = 'Found',
        
        [Switch]
        # Redirect all requests to exact destination (instead of relative to destination).
        $ExactDestination,
        
        [Switch]
        # Only redirect requests to content in site and/or path, but nothing below it.
        $ChildOnly
    )
    
    $statusArg = "/httpResponseStatus:$StatusCode"
    $exactDestinationArg =  "/exactDestination:$ExactDestination"
    $childOnlyArg = "/childOnly:$ChildOnly"
    
    Write-Host "Updating IIS settings for $SiteName/$Path to redirect to $destination."
    Invoke-AppCmd set config "$SiteName/$Path" /section:httpRedirect /enabled:true /destination:$destination $statusArg $exactDestinationArg $childOnlyArg /commit:apphost
}

function Set-IisSslFlags
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        # The website whose SSL flags should be modifed.
        $SiteName,
        
        [Parameter()]
        # The path to the folder/virtual directory/application under the website whose SSL flags should be set.
        $Path = '',
        
        [Switch]
        # Should SSL be required?
        $RequireSsl,
        
        [Switch]
        # Should client certificates be accepted?
        $AcceptClientCertificates,
        
        [Switch]
        # Should client certificates be required?
        $RequireClientCertificates,
        
        [Switch]
        # Should 128-bit SSL be supported?
        $Enable128BitSsl
    )
    
    $flags = @()
    if( $RequireSSL -or $RequireClientCertificates )
    {
        $flags += 'Ssl'
    }
    
    if( $AcceptClientCertificates )
    {
        $flags += 'SslNegotiateCert'
    }
    
    if( $RequireClientCertificates )
    {
        $flags += 'SslRequireCert'
    }
    
    if( $Enable128BitSsl )
    {
        $flags += 'Ssl128'
    }
    
    if( $pscmdlet.ShouldProcess( "$SiteName/$Path", "set SSL flags" ) )
    {
        Invoke-AppCmd set config "$SiteName/$Path" "-section:system.webServer/security/access" "/sslFlags:""$($flags -join ',')""" /commit:apphost
    }
}

function Set-IisWebsiteSslCertificate
{
    <#
    .SYNOPSIS
    Sets a website's SSL certificate.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the website whose SSL certificate is being set.
        $SiteName,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The thumbprint of the SSL certificate to use.
        $Thumbprint,

        [Parameter(Mandatory=$true)]        
        [Guid]
        # A GUID that uniquely identifies this website.  Create your own.
        $ApplicationID
    )
    
    $site = Get-IisWebsite -SiteName $SiteName
    if( -not $site ) 
    {
        Write-Error "Unable to find website '$SiteName'."
        return
    }
    
    $site.Bindings | Where-Object { $_.Protocol -eq 'https' } | ForEach-Object {
        $ipAddress = $_.IPAddress
        if( $ipAddress -eq '*' )
        {
            $ipAddress = '0.0.0.0'
        }
        Set-SslCertificateBinding -IPPort "$IPAddress`:$($_.Port)" -ApplicationID $ApplicationID -Thumbprint $Thumbprint
    }
}

function Set-IisWindowsAuthentication
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        # The site where Windows authentication should be set.
        $SiteName,
        
        [Parameter()]
        # The optional path where Windows authentication should be set.
        $Path = '',
        
        [Switch]
        # Disable Windows authentication.  Otherwise, it is enabled.
        $Disabled,
        
        [Switch]
        # Turn on kernel mode.  Default is false.
        $UseKernelMode
    )
    
    $enabledArg = 'true'
    if( $Disabled )
    {
        $enabledArg = 'false'
    }
    
    $useKernelModeArg = 'false'
    if( $UseKernelMode )
    {
        $useKernelModeArg = 'true'
    }
    
    if( $pscmdlet.ShouldProcess( "$SiteName/$Path", "set Windows authentication" ) )
    {
        Invoke-AppCmd set config "$SiteName/$Path" '-section:windowsAuthentication' /enabled:$enabledArg /useKernelMode:$useKernelModeArg /commit:apphost
    }
}

function Test-IisAppPoolExists
{
    <# 
    .SYNOPSIS
    Checks if an app pool exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the app pool.
        $Name
    )
    
    $apppools = Invoke-AppCmd list apppool
    foreach( $apppool in $apppools )
    {
        if( $apppool -match "^APPPOOL ""$Name""" )
        {
            return $true
        }
    }
    return $false
}

function Test-IisWebsiteExists
{
    param(
        [Parameter(Mandatory=$true)]
        # The website whose existence should be tested
        $Name
    )
    
    $output = Invoke-AppCmd list site -ErrorAction SilentlyContinue
    foreach( $line in $output )
    {
        if( $line -like "SITE ""$Name""*" )
        {
            return $true
        }
    }
    return $false
}

function Unlock-IisBasicAuthentication
{
    <#
    .SYNOPSIS
    Unlocks the system.webServer/security/authentication/windowsAuthentication section in the IIS server configuration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    )
    
    $commonParams = @{}
    if( $pscmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf') )
    {
        $commonParams.WhatIf = $true
    }
    
    Unlock-IisConfigSection -Name basicAuthentication @commonParams
}

function Unlock-IisCgi
{
    <#
    .SYNOPSIS
    Unlocks the system.webServer/cgi section in the IIS server configuration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    )
    
    $commonParams = @{}
    if( $pscmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf') )
    {
        $commonParams.WhatIf = $true
    }
    
    Unlock-IisConfigSection -Name cgi @commonParams
}

function Unlock-IisConfigSection
{
    <#
    .SYNOPSIS
    Unlocks a section in the IIS server configuration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the section to unlock.  For a list of sections, run
        #
        #    > C:\Windows\System32\inetsrv\appcmd.exe unlock config /section:?
        $Name
    )
    
    if( $pscmdlet.ShouldProcess( $Name, 'unlocking config section' ) )
    {
        Write-Host "Unlocking IIS configuration section '$Name'."
        Invoke-AppCmd unlock config "/section:$Name"
    }
}

function Unlock-IisWindowsAuthentication
{
    <#
    .SYNOPSIS
    Unlocks the system.webServer/security/authentication/windowsAuthentication section in the IIS server configuration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    )
    
    $commonParams = @{}
    if( $pscmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf') )
    {
        $commonParams.WhatIf = $true
    }
    
    Unlock-IisConfigSection -Name windowsAuthentication @commonParams
}
