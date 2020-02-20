# Run network diagnostics for AVEVA Insight Publisher
#
# ---------------------------------------------------
#
# Typical control network architectures create a lot of obstacles for publishing data to AVEVA Insight.
# This Powershell script will report many relavant settings and perform some basic diagnostic tests
# of network connectivity. Use this with computers running any of the following:
#
#    AVEVA Historian
#    Insight Publisher
#    DMZ Secure Link
#
# Modified: 20-Feb-2020
# By:       E. Middleton
#
# To enable Powershell scripts use:
#    Set-ExecutionPolicy unrestricted
#
# To disable Powershell scripts use (after using the script):
#    Set-ExecutionPolicy restricted
#

# ==============================================================
# BEFORE USING: Update the variables below for your environment
#

# PROXY: If using DMZ Secure Link, use the IP address of the computer running it and the configured port 
# To use the user proxy configured in Windows' "Internet Options" settings, leave these proxy settings blank
$ProxyIP = ""
$ProxyPort = ""

# INSTANCE: Most tests apply generally, but if you want to specifically test your region, update the name below
$InsightHost = "online.wonderware.com"
$CheckBlockedUri = "http://www.apple.com"

#
# END OF SITE-SPECIFIC SETTINGS
# ==============================================================

Function Check-Ping ($HostOrIP) {
    $result = Test-Connection -ComputerName $HostOrIP -Count 1 -Quiet
    return $result
}

Function Check-Port($HostOrIP, $Port) {
    $client = New-Object Net.Sockets.TcpClient
    $client.ReceiveTimeout = 1000
    $client.SendTimeout = 1000
    $result = $false
    try {
        $client.Connect($HostOrIP, $Port)
        $result = $true
    } catch {
        $result = $false
    }
    $client = $null
    return $result
}

Function Check-Route( $HostOrIP ) {
    try {
        $result = Find-NetRoute -RemoteIPAddress (Get-IpAddress $HostOrIP)
    } catch {
        $result = $null
    }
    return $result
}

Function Check-Http( $Uri, $ProxyUri, $ReturnData  ) {
    $status = 0
    $Http = [System.Net.WebRequest]::Create($Uri)
    $Http.Method = "GET"
    $Http.Accept = "text/html,application/json"
    $Http.AllowAutoRedirect = $false
    $Http.Proxy = New-Object System.Net.WebProxy($ProxyUri)
    $Http.Timeout = 10000
    $Http.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36"

    if ( [Enum]::GetValues([Net.SecurityProtocolType]) -Like "Tls12" ) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 
    }

    try {
        $response = $Http.GetResponse()
        $status = [int]$response.StatusCode
        if ($ReturnData -and ($status -eq 200 -or $status -eq 301) ) {
            $stream = $response.GetResponseStream()
            $reader = New-Object IO.StreamReader $stream
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $data = $json.Data | ConvertFrom-Json
            $json = $null
            $reader.Close()
            $reader = $null
            $stream.Close()
            $stream = $null
            $status = $data
        }
        $response.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.HResult -eq -2146233087 -or $_.Exception.Status -eq [System.Net.WebExceptionStatus]::SendFailure) {
            $status = -1
        } else {
            $status = [int]$_.Exception.Status
        }
    } catch {
        Write-Verbose "Error attempting to get '$($Uri)': $($_.Exception.Message)"
        if ($_.Exception.HResult) {
            $status = $_.Exception.HResult
        }
    } finally {
        $Http = $null
        $response = $null
    }
    Write-Verbose "Host: $($Uri)  Proxy: $($ProxyUri)  Status: $($status)  Protocol(s): $([Net.ServicePointManager]::SecurityProtocol)"
    return $status
}


Function Get-FirstAddress ( $AddressList ) {
    $first = $AddressList | Select-Object -First 1
    return $first.Trim()
}

Function Get-StatusText ( $status ) {
    $message = $status.ToString()
    try {
        $message += "-" + [System.Net.WebExceptionStatus]$status
    } catch {
    }
    return $message
}

Function Get-UserProxy
 { # from http://obilan.be 
    $proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
    if ($proxy)
    {
        if ($proxy -ilike "*=*")
        {
            $proxy = $proxy -replace "=","://" -split(';') | Select-Object -First 1
        }
        else
        {
            $proxy = "http://" + $proxy
        }
    }    
    return $proxy
}

Function Get-IpAddress ($HostOrIP) {
    $nameType = [Uri]::CheckHostName($HostOrIP)  
    if ($nameType -eq [UriHostNameType]::IPv4 -or$nameType -eq [UriHostNameType]::IPv6) {
        $ip = $HostOrIP
    } else {
        try {
            $ip = ([System.Net.Dns]::GetHostEntry($HostOrIP).AddressList | Select-Object -First 1).IPAddressToString
        } catch {
            $ip = ""
        }
    }
    return $ip
}

Function Get-SystemProxy {
# https://www.powershellgallery.com/packages/Get-InternetAccessInfo/0.2/Content/Get-InternetAccessInfo.psm1
       try {
           $Conprx = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttpSettings
       } catch {
            $Conprx = $null
       } finally {
            if ($Conprx) {
            $proxylength = $Conprx[12]            
                if ($proxylength -gt 0) {            
                    $result = "http://" + -join ($Conprx[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})            
                } else {                                
                    $result = $null
                }
            } else {
                    $result = $null
            }
       }
       return $result                  
}


Function Report-Ping($label, $hostname) 
{
    $Response = Check-Ping $hostname
    if ($Response) {
        Write-Host -ForegroundColor Green "Successfully reached $($label) at '$($hostname)' via 'ping'"
    } else {
        Write-Host -ForegroundColor Red "Failed 'ping' to $($label) at '$($hostname)'"
        Write-Host -ForegroundColor Cyan "    This could mean that ICMP is disabled, the system is offline or that TCP route/gateway is not correctly configured"
    }
}

Function Report-Port($label, $hostname, $port) 
{
    $TcpResult = $null
    $TcpResult = Check-Port $hostname $port
    if ($TcpResult) {
        Write-Host -ForegroundColor Green "Successfully reached $($label) at '$($hostname)' on port '$($port)'"
    } else {
        Write-Host -ForegroundColor Red "Failed to reach $($label) on port '$($port)' at '$($hostname)'"
        if (Check-Ping $hostname) {
            Write-Host -ForegroundColor Green "Successfully reached $($label) at '$($hostname)' using 'ping'"
            Write-Host -ForegroundColor Cyan "    This means the TCP route is working, but the port is blocked by a hardware or software firewall or the service is not running"
        } else {
            $route = Check-Route $hostname
            if ($route) {
                Write-Host -ForegroundColor Red "Failed 'ping' test to '$($hostname)' from '$(Get-FirstAddress($route.IPAddress))' using route via '$(Get-FirstAddress($Route.NextHop))'"
            } else {
                Write-Host -ForegroundColor Red "Failed 'ping' test to '$($hostname)'"
            }
            Write-Host -ForegroundColor Cyan "    This may mean the TCP route/gateway is not correctly configured"
            $route = $null
        }
    }
    return $TcpResult
}

Function Report-Route($label, $Address) {
    $Route = Check-Route( Get-IpAddress $Address )
    if ($Route) {
        $next = Get-FirstAddress($Route.NextHop)
        if ($next -ne "0.0.0.0") {
            Write-Host "Route to $($label) at '$($Address)' is on '$(Get-FirstAddress($Route.IPAddress))' via gateway of '$($next)' using interface #$($Route.InterfaceIndex[0])"
            Report-Ping "gateway" $next
        } else {
            Write-Host "The $($label) is on the local network for '$(Get-FirstAddress($Route.IPAddress))' using interface #$($Route.InterfaceIndex[0])"
        }

        if (!$Route.State -Like "Alive" ) {
            $nic = Get-NetIPInterface -InterfaceIndex $($Route.InterfaceIndex[0])
            Write-Host -ForegroundColor Red "Interface #$($Route.InterfaceIndex[0]) is not currently active"
        }
    } else {
        Write-Host "Route details for $($Label) are not available"
    }
}

Function Report-Uri($Uri, $ProxyUri, $Required) 
{
    $HttpResult = $null
    $HttpResult = Check-Http $Uri $ProxyUri $false
    $hostname = ([System.Uri]$Uri).Host
    if ($HttpResult -eq 200) {
        Write-Host -ForegroundColor Green "Successfully reached '$($hostname)' via proxy"
    } else {
        if ($Required) {
            Write-Host -ForegroundColor Red "Failed to reach host '$($hostname)' via proxy"
        } else {
            Write-Host -ForegroundColor Red "Failed to reach optional host '$($hostname)' via proxy"
        }
        Write-Host -ForegroundColor Cyan "    This may mean the proxy is not correctly configured"
        Report-Hostname ([System.Uri]$Uri).Host $false
    }
#    Report-Hostname $Uri $false
    return $HttpResult
}

Function Report-Hostname( $hostname, $Required )
{
    if ([Uri]::CheckHostName($hostname) -eq [UriHostNameType]::IPv4 -or [Uri]::CheckHostName($hostname) -eq [UriHostNameType]::IPv6) {
        Write-Verbose "'$($hostname)' is recognized as an IP address"
    } else {
        try {
            $ip = ([System.Net.Dns]::GetHostEntry($hostname)).AddressList | Select-Object -ExpandProperty "IPAddressToString"
            if ([Uri]::CheckHostName($hostname) -eq [UriHostNameType]::Dns ) {
                Write-Host -ForegroundColor Green "Successfully resolved hostname '$($hostname)' to '$($ip -Join "', '")'"
            } else {
                if ([Uri]::CheckHostName($hostname) -eq [UriHostNameType]::Basic) {
                    Write-Host -ForegroundColor Green "Successfully resolved hostname '$($hostname)' as basic address '$($ip -Join "', '")'"
                } else {
                    if ($Required) {
                        Write-Host -ForegroundColor Cyan "    Potential problem resolving '$($hostname)' as '$($ip)'"
                    }
                }
            }
        } catch {
            if ($Required) {
                Write-Host -ForegroundColor Red "Failed to resolve hostname '$($hostname)'"
            }
        }
    }
}

Function ValueFromRegistry( $RegKey, $RegValue )
{
    try {
        $Values = Get-ItemProperty -Path $RegKey  -ErrorAction SilentlyContinue
        if ([bool]($Values.PSObject.Properties | where {$_.Name -eq $RegValue})) {
            $Value = $Values | Select-Object -ExpandProperty $RegValue
        } else {
            $Value = ""
        }
    } catch {
        $Value = ""
    }
    return $Value
}

Function GetFileVersion( $Label, $Path ) {
    $info = $Label + ": Not found"
    if ( (![String]::IsNullOrEmpty($Path)) -and (Test-Path $Path -PathType leaf)) {
        $info = $Label + ": "
        $info += [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
        $info += " " + (Get-ItemProperty $Path).LastWriteTime.Date.ToString("dd-MMM-yyyy")
    }
    return $info
}

# Script utility variables
$InsightUri = "https://" + $InsightHost
$InsecureInsightUri = "http://" + $InsightHost
$ProxyUri = ""
if ($ProxyIP -ne "" -and $ProxyPort -ne "") {
    $ProxyUri = "http://" + $ProxyIP + ":" + $ProxyPort
} else {
    $ProxyUri = Get-UserProxy
    $ProxyParts = $ProxyUri -replace "http://","" -split(':')
    $ProxyIP = Get-IpAddress( $ProxyParts[0] )
    $ProxyPort = $ProxyParts[1]
}

Write-Host ""
Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")"
$Environment = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$Arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$PSVersion = (Get-Host).Version
$FQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
$Addresses = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | Select-Object -ExpandProperty 'IPAddress') -Join ", "
$PSArch = ""
if ([Environment]::Is64BitProcess) {
    $PSArch = "64-bit"
} else {
    $PSArch = "32-bit"
}

Write-Host "$($FQDN)"
Write-Host "$($Environment.ProductName) $($Arch) $(if ($Environment.ReleaseId) {$Environment.ReleaseId}) ($($Environment.CurrentBuildNumber)), Powershell $($PSVersion.Major).$($PSVersion.Minor) ($($PSArch))"
$IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Host "Running as Administrator"
} else {
    Write-Host "Running as Standard User"
}

Write-Host "Powershell Security Protocols: $([Enum]::GetValues([Net.SecurityProtocolType]) -Like "Tls*" -Join ", ")"
$Crypto = ".NET Require Strong Cryptography: "
$TlsOkay = $false
if ( (ValueFromRegistry "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
    $Crypto += "Yes (default to TLS 1.2) 32-bit"
    if ( (ValueFromRegistry "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
        $Crypto += " and 64-bit"
        $TlsOkay = $true
    } else {
        $Crypto += " only"
    }
    Write-Host $Crypto
} else {
    if ( (ValueFromRegistry "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
        $Crypto += "Yes (default to TLS 1.2) 32-bit only"
        $TlsOkay = $true
        Write-Host $Crypto
    } else {
        $Crypto += "No (default to TLS 1.0)"
        Write-Host $Crypto
        Write-Host -ForegroundColor Cyan "   Publisher versions released before Dec-2018 will not be able to connect to Insight"
    }
}
# Display various proxy settings to let the user check for consistency
$UserProxy = Get-UserProxy
Write-Host "The user's 'Internet Options' proxy is '$($UserProxy)'"

$SystemProxy = Get-SystemProxy
Write-Host "The system WinHTTP proxy is '$($SystemProxy)'"
if ($SystemProxy -ne $ProxyUri -or $UserProxy -ne $ProxyUri -or $SystemProxy -ne $UserProxy) {
    Write-Host -ForegroundColor Cyan "    The user & system proxies should usually be consistent with '$($ProxyUri)'"
}

# Get summary information about all network interfaces
Write-Host "Addresses: $($Addresses)"
Write-Host "Gathering details about all network interfaces..."
$AllNics = @()
try {
    Get-NetIPConfiguration | ForEach-Object {
    if ($_.IPv4Address.Count -ge 1) {
        if ($_.IPv4DefaultGateway.Count -ge 1) {
            $gw = $_.IPv4DefaultGateway[0]
        } else {
            $gw = $null
        }

        $nicInfo = [ordered]@{
            ID = $_.InterfaceIndex
            Interface = $_.InterfaceDescription
            IPAddress = "$($_.IPv4Address[0].IPAddress)/$($_.IPv4Address[0].PrefixLength)"
            Source = $_.IPv4Address[0].PrefixOrigin
            Gateway = $gw.NextHop
            Destination = $gw.DestinationPrefix
            Network = $_.NetProfile.NetworkCategory
            Status = $_.NetProfile.IPv4Connectivity
            Type = "IPv4"
            Count = $_.IPv4Address.Count
        }
        $nic = New-Object -TypeName PSObject -Property $nicInfo
        $AllNics += $nic
    } 

    if ($_.IPv6Address.Count -ge 1) {
        if ($_.IPv6DefaultGateway.Count -ge 1) {
            $gw = $_.IPv6DefaultGateway[0]
        } else {
            $gw = $null
        }

        $nicInfo = [ordered]@{
            ID = $_.InterfaceIndex
            Interface = $_.InterfaceDescription
            IPAddress = "$($_.IPv6Address[0].IPAddress)/$($_.IPv6Address[0].PrefixLength)"
            Source = $_.IPv6Address[0].PrefixOrigin
            Gateway = $gw.NextHop
            Destination = $gw.DestinationPrefix
            Network = $_.NetProfile.NetworkCategory
            Status = $_.NetProfile.IPv6Connectivity
            Type = "IPv6"
            Count = $_.IPv6Address.Count
        }
        $nic = New-Object -TypeName PSObject -Property $nicInfo
        $AllNics += $nic
    }
}
$AllNics | Format-Table
} catch {
    Write-Host "Network details are not available"
}

# Get version details for relavant products
if ($Arch -eq "64-bit") {
    $BaseKey = "HKLM:\SOFTWARE\WOW6432Node"
} else {
    $BaseKey = "HKLM:\SOFTWARE"
}
Write-Host (GetFileVersion "Historian" ((ValueFromRegistry ($BaseKey + "\ArchestrA\Historian\Setup") "InstallPath") + "aahCfgSvc.exe"))
Write-Host (GetFileVersion "Publisher" (ValueFromRegistry ("HKLM:\SOFTWARE\ArchestrA\HistorianPublisher\Setup") "LaunchTarget"))
Write-Host (GetFileVersion "DMZ Secure Link" (ValueFromRegistry ("HKLM:\SOFTWARE\ArchestrA\SecureLink\Setup") "LaunchTarget"))

Write-Host " "
Write-Host  "Testing connectivity to '$($InsightUri)' via proxy '$($ProxyUri)'"

# Resolve names

# Confirm we can resolve the names (but only if these aren't IP address)
Report-Hostname ([System.Uri]$ProxyUri).Host $true
if ( ([System.Uri]$ProxyUri).Host -notlike ([System.Uri]$UserProxy).Host ) {
    Report-Hostname ([System.Uri]$UserProxy).Host $true
}
if ( ([System.Uri]$ProxyUri).Host -notlike ([System.Uri]$SystemProxy).Host -and ([System.Uri]$SystemProxy).Host -notlike ([System.Uri]$UserProxy).Host ) {
    Report-Hostname ([System.Uri]$SystemProxy).Host $false
}
Report-Hostname ([System.Uri]$InsightUri).Host $false

# Check the route
Report-Route "proxy" $ProxyIP

# Use variations on the lines below, uncommented, for other test cases
#Check-Port "rdp" "myhostname" 3389

# Confirm we can reach the proxy/DMZ Secure Link
if (Report-Port "proxy" $ProxyIP $ProxyPort) {
    # Confirm the proxy can reach a AVEVA Insight endpoint
    $HttpResult = $null
    $HttpResult = Check-Http $InsightUri $ProxyUri $false

    # Check the certificate (adapted from https://communary.net/2017/08/16/retrieve-ssl-certificate-information/)
    # This helps confirm we're really reaching the site and not just getting a response from the proxy
    if ($HttpResult -eq 200) {
        Write-Host -ForegroundColor Green "Successfully connected to '$($InsightUri)' via proxy"

        try {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            $CertRequest = [System.Net.HttpWebRequest]::Create($InsightUri)
            $CertRequest.Proxy = New-Object System.Net.WebProxy($ProxyUri)
            $CertRequest.KeepAlive = $false
            $CertRequest.Timeout = 5000
            $CertRequest.ServicePoint.ConnectionLeaseTimeout = 5000
            $CertRequest.ServicePoint.MaxIdleTime = 5000
        } catch [System.Net.WebException] {
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
                # We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
                Write-Host -ForegroundColor Red "The certifcate for '$($InsightUri)' is not trusted"
                Write-Host -ForegroundColor Cyan "   This may be beause of an upstream proxy or other security layer that is intercepting requests"
            }
            else
            {
                Write-Warning $_.Exception.Message
            }
        } catch {
            Write-Warning $_.Exception.Message
        }

        if (($CertRequest.ServicePoint.Certificate) -and ($CertRequest.ServicePoint.Certificate.Handle -ne 0)) {
            if ($CertRequest.ServicePoint.Certificate.Subject -inotlike"*O=AVEVA*") {
                Write-Host -ForegroundColor Red "The '$($InsightUri)' appears to be impersonated by another issuer: $($CertRequest.ServicePoint.Certificate.Issuer)"
                Write-Host -ForegroundColor Cyan "   It may be getting replaced by an upstream proxy or other security layer"
            } else {
                Write-Host -ForegroundColor Green "The certifcate for '$($InsightUri)' appears to be valid"
            }
        } else {
            Write-Host -ForegroundColor Red "Unable to get certificate for '$($InsightUri)'"
            Write-Host -ForegroundColor Cyan "    This may mean requests are being intercepted by an upstream proxy or other security layer."
        }
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        
        # DMZ Secure Link: Confirm a site that is not part of the whitelist is blocked
        $BlockedStatus = Check-Http $CheckBlockedUri $ProxyUri $false
        if ($BlockedStatus -eq 406) {
            Write-Host -ForegroundColor Green "DMZ Secure Link correctly blocked access to '$($CheckBlockedUri)'"
        } else {
            Write-Host -ForegroundColor Red "Access to '$($CheckBlockedUri)' was NOT blocked"
            Write-Host -ForegroundColor Cyan "    If the proxy specified is DMZ Secure Link, that should be blocked. Other proxies might permit access."
        }

        $list = Check-Http($InsightUri + "/apis/wwocorefunctions/api/OnlineConfigPush?config=publisher") $ProxyUri $true
        if ($list.PSobject.Properties.Name -contains "URLs") {
             Write-Host -ForegroundColor Green "Successfully retrieved list of key URLs used by Insight from '$($InsightUri)'"
             $list.URLs | ForEach-Object -Process { $HttpResult = Report-Uri $_.URL $ProxyUri $_.AccessMandatory }
        } else {
             Write-Host -ForegroundColor Red "Unable to retrieve list of needed sites from Insight"
             Write-Host -ForegroundColor Cyan "    This may mean the proxy is not correctly configured"
        }

    } else {
        if ($HttpResult -eq -1) {
            Write-Host -ForegroundColor Red "Failed HTTPS connection to '$($InsightUri)' via proxy at '$($ProxyUri)' (Status $(Get-StatusText($HttpResult)))"
            if (!$TlsOkay) {
                Write-Host -ForegroundColor Cyan "    This failure was likely because TLS 1.2 was not available to Powershell"
                Write-Host -ForegroundColor Cyan "    If your Publisher was released before Dec-2018, you need to force strong cryptography"
                Write-Host -ForegroundColor Cyan "    You can use the Powershell script below, run as an 'Administrator':"

                Write-Host -ForegroundColor Gray "      `$tls = [Net.ServicePointManager]::SecurityProtocol"
                Write-Host -ForegroundColor Gray "      Write ""Current TLS Settings: `${tls}""" 
                Write-Host -ForegroundColor Gray "      if ([Environment]::Is64BitOperatingSystem)"
                Write-Host -ForegroundColor Gray "      {"
                Write-Host -ForegroundColor Gray "       Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord"
                Write-Host -ForegroundColor Gray "       Write ""64-bit .NET applications will now require strong cryptography"""
                Write-Host -ForegroundColor Gray "      }"
                Write-Host -ForegroundColor Gray "      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord"
                Write-Host -ForegroundColor Gray "      Write ""32-bit .NET applications will now require strong cryptography"""
            }
            Write-Host "Retrying with insecure connection (HTTP) to '$($InsecureInsightUri)' via proxy '$($ProxyUri)'"
            $InsecureResult = Check-Http $InsecureInsightUri $ProxyUri $false
            if ($InsecureResult -eq 301) {
                Write-Host -ForegroundColor Green "Successfully connected to '$($InsecureInsightUri)' (insecure) via proxy"
            } else {
                Write-Host -ForegroundColor Red "Failed insecure HTTP connection to '$($InsecureInsightUri)' via proxy at '$($ProxyUri)' (Status $(Get-StatusText($InsecureResult)))"
                Write-Host -ForegroundColor Cyan "    This may be a problem with the upstream proxy or Internet connectivity"
            }
    } else {
        Write-Host -ForegroundColor Red "Failed HTTPS connection to '$($InsightUri)' via proxy at '$($ProxyUri)' (Status $(Get-StatusText($HttpResult)))"
        Write-Host -ForegroundColor Cyan "    The outbound connections from the proxy may be blocked or there may be security protocol problems"
        } 
    }
} else {
    Write-Host -ForegroundColor Red "Failed to open TCP connection to proxy at '$($ProxyUri)'"
    Write-Host -ForegroundColor Cyan "    The port on the proxy may be blocked by a hardware or software firewall or it may be listening on a different IP address"

    # Try to 'ping' proxy (won't always work, even when connections work)
    Report-Ping "proxy" $ProxyIP

}

Write-Host "Tests completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")"
