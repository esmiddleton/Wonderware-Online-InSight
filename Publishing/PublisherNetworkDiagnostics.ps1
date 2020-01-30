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
# Modified: 30-Jan-2020
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
$ProxyIP = "192.168.80.15"
$ProxyPort = 8080

# INSTANCE: Most tests apply generally, but if you want to specifically test your region, update the name below
$InsightHost = "online.wonderware.com"
$CheckBlockedUri = "http://www.apple.com"

#
# END OF SITE-SPECIFIC SETTINGS
# ==============================================================

# Script utility variables
$InsightUri = "https://" + $InsightHost
$ProxyUri = "http://" + $ProxyIP + ":" + $ProxyPort

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
        $result = Find-NetRoute -RemoteIPAddress $HostOrIP
    } catch {
        $result = $null
    }
    return $result
}

Function Check-Http( $Uri, $ProxyUri ) {
    $status = 0
    $Http = [System.Net.WebRequest]::Create($Uri)
    $Http.Method = "GET"
    $Http.Accept = "text/html"
    $Http.Proxy = New-Object System.Net.WebProxy($ProxyUri)
    $Http.Timeout = 5000
    $Http.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36"

    if ( [Enum]::GetValues([Net.SecurityProtocolType]) -Like "Tls12" ) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 
        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::ssl
    }

    try {
        $response = $Http.GetResponse()
        $status = [int]$response.StatusCode
    } catch [System.Net.WebException] {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::ProtocolError) {
            $status = 406
        } else {
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
                $status = -2
            } else {
                if ($_.Exception.HResult -eq -2146233087 -or $_.Exception.InnerException.Message -eq "The underlying connection was closed: An unexpected error occurred on a send.") {
                    $status = -1
                } else {
                    $status = [int]$_.Exception.Status
                }
            }
        }
    } catch {
        Write-Verbose "Error attempting to get '$($Uri)': $($_.Exception.Message)"
        if ($_.Exception.HResult) {
            $status = $_.Exception.HResult
        }
    } finally {
        $response = $null
    }
    $Http = $null
    Write-Verbose "Host: $($Uri)  Proxy: $($ProxyUri)  Status: $($status)  Protocol(s): $([Net.ServicePointManager]::SecurityProtocol)"
    return $status
}


Function Get-Address ( $AddressList ) {
    $first = $AddressList | Select-Object -First 1
    return $first.Trim()
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
    return $Response
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
                Write-Host -ForegroundColor Red "Failed 'ping' test to '$($hostname)' from '$(Get-Address($route.IPAddress))' using route via '$(Get-Address($Route.NextHop))'"
            } else {
                Write-Host -ForegroundColor Red "Failed 'ping' test to '$($hostname)'"
            }
            Write-Host -ForegroundColor Cyan "    This may mean the TCP route/gateway is not correctly configured"
            $route = $null
        }
    }
    return $TcpResult
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


Write-Host ""
Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")"
$Environment = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$Arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$PSVersion = (Get-Host).Version
$FQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
$Addresses = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | Select-Object -ExpandProperty 'IPAddress') -Join ", "

Write-Host "$($FQDN)"
Write-Host "$($Environment.ProductName) $($Arch) $(if ($Environment.ReleaseId) {$Environment.ReleaseId}) ($($Environment.CurrentBuildNumber)), Powershell $($PSVersion.Major).$($PSVersion.Minor)"
Write-Host "Addresses: $($Addresses)"

Write-Host "Powershell Security Protocols: $([Enum]::GetValues([Net.SecurityProtocolType]) -Like "Tls*" -Join ", ")"
$Crypto = ".NET Strong Cryptography: "
if ( (ValueFromRegistry "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
    $Crypto += "32-bit TLS 1.2"
    if ( (ValueFromRegistry "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
        $Crypto += ", 64-bit TLS 1.2"
    }
    Write-Host $Crypto
} else {
    if ( (ValueFromRegistry "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" "SchUseStrongCrypto") -eq 1 ) {
        $Crypto += "32-bit TLS 1.2"
        Write-Host $Crypto
    } else {
        $Crypto += "TLS 1.0"
        Write-Host $Crypto
        Write-Host -ForegroundColor Cyan "   Publisher versions released before December 2018 will not be able to connect to Insight"
    }
}

Write-Host  ""
if ($Arch -eq "64-bit") {
    $BaseKey = "HKLM:\SOFTWARE\WOW6432Node"
} else {
    $BaseKey = "HKLM:\SOFTWARE"
}
Write-Host (GetFileVersion "Historian" ((ValueFromRegistry ($BaseKey + "\ArchestrA\Historian\Setup") "InstallPath") + "aahCfgSvc.exe"))
Write-Host (GetFileVersion "Publisher" (ValueFromRegistry ($BaseKey + "\ArchestrA\HistorianPublisher\Setup") "LaunchTarget"))
Write-Host (GetFileVersion "DMZ Secure Link" (ValueFromRegistry ($BaseKey + "\ArchestrA\SecureLink\Setup") "LaunchTarget"))

Write-Host  ""
Write-Host  "Testing connectivity to '$($InsightUri)' via proxy '$($ProxyUri)'"

# Use variations on the lines below, uncommented, for other test cases
#PortCheck "rdp" "myhostname" 3389

# Confirm we can reach the proxy/DMZ Secure Link
if (Report-Port "proxy" $ProxyIP $ProxyPort) {
    # Confirm the proxy can reach a AVEVA Insight endpoint
    $HttpResult = $null
    $HttpResult = Check-Http $InsightUri $ProxyUri $null

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
        $BlockedStatus = Check-Http $CheckBlockedUri $ProxyUri
        if ($BlockedStatus -eq 406) {
            Write-Host "DMZ Secure Link correctly blocked access to '$($CheckBlockedUri)'"
        } else {
            Write-Host -ForegroundColor Red "Access to '$($CheckBlockedUri)' was NOT blocked"
            Write-Host -ForegroundColor Cyan "    If the proxy specified is DMZ Secure Link, that should be blocked. Other proxies might permit access."
        }
    } else {
        if ($HttpResult -eq -1) {
            Write-Host -ForegroundColor Red "Failed HTTP connection because TLS 1.2 was not available to Powershell"
            Write-Host -ForegroundColor Cyan "    Your system may require updates to get support for the required security protocols for Insight"
    } else {
        Write-Host -ForegroundColor Red "Failed HTTP connection to '$($InsightUri)' via proxy at '$($ProxyUri)' (Status $($HttpResult))"
        Write-Host -ForegroundColor Cyan "    The outbound connections from the proxy may be blocked or there may be security protocol problems"
        } 
    }
} else {
    Write-Host -ForegroundColor Red "Failed to open TCP connection to proxy at '$($ProxyUri)'"
    Write-Host -ForegroundColor Cyan "    The port on the proxy may be blocked by a hardware or software firewall or it may be listening on a different IP address"

    # Try to 'ping' proxy (won't always work, even when connections work)
    Report-Ping "proxy" $ProxyIP

    # Check the route
    $Route = Check-Route $ProxyIP
    if ($Route) {
        $next = Get-Address($Route.NextHop)
        if ($next -ne "0.0.0.0") {
            Write-Host "Route to proxy is on '$($next)' via '$($next)'"
            Report-Ping "gateway" $next
        } else {
            Write-Host "Proxy is on the local network for '$(Get-Address($Route.IPAddress))'"
        }
    } else {
        Write-Host "Route details not available"
    }
}

# Display other proxy settings to let the user check for consistency
$UserProxy = Get-UserProxy
Write-Host "The user's 'Internet Options' proxy is '$($UserProxy)'"

$SystemProxy = Get-SystemProxy
Write-Host "The system WinHTTP proxy is '$($SystemProxy)'"
if ($SystemProxy -ne $ProxyUri -or $UseProxy -ne $ProxyUri -or $SystemProxy -ne $UserProxy) {
    Write-Host -ForegroundColor Cyan "    The user & system proxies should usually be consistent with '$($ProxyUri)'"
}
