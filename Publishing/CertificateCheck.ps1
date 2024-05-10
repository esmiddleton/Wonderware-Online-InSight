# Run detailed certificate diagnostics for a specific URL
#
# ---------------------------------------------------
#
# This is extracted from the more complete Publisher Diagnostic script
#
# Modified: 9-May-2024
# By:       E. Middleton
#
# To enable Powershell scripts use:
#    Set-ExecutionPolicy unrestricted
#
# To disable Powershell scripts use (after using the script):
#    Set-ExecutionPolicy restricted
#

# ==============================================================
# BEFORE USING: Update the last line of the script for your environment
# ==============================================================


$VerbosePreference = "Continue" # Include more detailed tracing output

function fnLN {
    $MyInvocation.ScriptLineNumber
}

[Net.ServicePointManager]::ServerCertificateValidationCallback = $null
Function Report-CertValidity( $CertUri, $ProxyUri, $Owner ) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        $UriToCheck = $sender.RequestUri.AbsoluteUri

        Write-Host "Checking validity of the certificate for '$UriToCheck' issued by '$($Certificate.IssuerName.Name)'"
        #If ($sslPolicyErrors

        $problemFound = $false
        If (($sslPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None) -or ($VerbosePreference -eq "Continue")) {
            $certIndex = 1
            #$chain.ChainElements | ForEach-Object {
            ($chain.ChainElements.Count-1)..0 | ForEach-Object {
                #$ce = $_
                $ce = $chain.ChainElements[$_]
                $cert = $ce.Certificate
                Write-Host -ForegroundColor Gray "`t$($certIndex): $($cert.Subject)' from '$(($cert.IssuerName.Name -split "," -split "=")[1]))"
                $certIndex += 1

                $crlDistributionPoints = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "CRL Distribution Points" }

                # Output the CRL Distribution Points
                foreach ($point in $crlDistributionPoints) {
                    $crl = $point.Format(0) -split "URL=" -split "," | Where-Object {$_.ToString() -like "http*"}
                    Write-Host -ForegroundColor Gray "`t`tCRL: $(($crl -join ", "))"
                }
                if ([DateTime]::Now -gt $cert.NotAfter) {
                    Write-Host -ForegroundColor Red "`t`tThe certificate '$($cert.Subject)' in the chain for '$UriToCheck' expired $($cert.NotAfter.ToString('dd-MMM-yyyy'))"
                    Write-Host -BackgroundColor Black -ForegroundColor Cyan "`t`tThis may be because your trusted certificate authorities are out of date or because of problems with your system time ($([DateTime]::Now.ToString('dd-MMM-yyyy HH:mm')))"
                    $problemFound = $true
                    return $false
                }

                if ([DateTime]::Now -lt $cert.NotBefore) {
                    Write-Host -ForegroundColor Red "`t`tThe certificate '$($cert.Subject)' in the chain for '$UriToCheck' is not valid until $($cert.NotBefore.ToString('dd-MMM-yyyy'))"
                    Write-Host -BackgroundColor Black -ForegroundColor Cyan "`t`tThis may be because of problems with your system time ($([DateTime]::Now.ToString('dd-MMM-yyyy HH:mm')))"
                    $problemFound = $true
                    return $false
                } else {
                    If (([DateTime]::Now - $cert.NotBefore).TotalDays -lt 20) {
                        Write-Host "`t`tThis is a relatively new certificate which became valid $($cert.NotBefore.ToString('dd-MMM-yyyy'))"
                    }
                }

                if ($ce.ChainElementStatus.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) {
                    # Self-signed certificates with an untrusted root
                    Write-Host -ForegroundColor Red "`t`tThe root certificate for '$UriToCheck' was not trusted"
                    Write-Host -BackgroundColor Black -ForegroundColor Cyan "`t`tThis may be because your trusted certificate authorities are out of date"
                    $problemFound = $true
                    return $false
                }

                if (($ce.ChainElementStatus.Count -gt 0) -and ($ce.ChainElementStatus.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError)) {
                    # If there are any other errors in the certificate chain,
                    # the certificate is invalid, so the method returns false.
                    Write-Host -ForegroundColor Red "`t`tThere where errors in the certificate '$($cert.Subject)' in the chain for '$UriToCheck' ($($ce.ChainElementStatus.Status))"
                    Write-Host -BackgroundColor Black -ForegroundColor Cyan "`t`tDon't know why"
                    $problemFound = $true
                    return $false
                }
            }
        }

        if ((!$problemFound) -and ($sslPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None)) {
            Write-Host -ForegroundColor Red "The certificate for '$UriToCheck' did not meet the policy requirements"
            Write-Host -BackgroundColor Black -ForegroundColor Cyan "   This may be because of your group policy settings"
            $problemFound = $true
            return $false # Certificate is bad
        }

        # When processing reaches this point, the certificate is considered valid.
        return (!$problemFound)
    }

    try {
        if ( [Enum]::GetValues([Net.SecurityProtocolType]) -Like "Tls12" ) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 
        }
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 1024

        $noCachePolicy = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore)

        $CertRequest = [System.Net.HttpWebRequest]::Create($CertUri)
        $CertRequest.Method = "GET"
																	  
        $CertRequest.KeepAlive = $false
        $CertRequest.Timeout = 5000
        $CertRequest.ServicePoint.ConnectionLeaseTimeout = 5000
        $CertRequest.ServicePoint.MaxIdleTime = 5000
        $CertRequest.CachePolicy = $noCachePolicy
        if ( $ProxyUri -ne "" ) {
            $CertRequest.Proxy = New-Object System.Net.WebProxy($ProxyUri)
        } else {
            $CertRequest.Proxy = $null
        }
        $Response = $CertRequest.GetResponse()
	    $Response.Dispose()
 	    $Response = $null
    } catch [System.Net.WebException] {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
            # We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
            Write-Host -ForegroundColor Red "The certifcate for '$($CertUri)' is not trusted"
            Write-Host -BackgroundColor Black -ForegroundColor Cyan "   This may be because of an upstream proxy or other security layer that is intercepting requests"
        } else {
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout) {
                Write-Host -ForegroundColor Yellow "Validating the certifcate for '$($CertUri)' timed out"
                Write-Host -BackgroundColor Black -ForegroundColor Cyan "   This is likely because the certificate revocation list wasn't accessible"
            } else {
                if ([int]$_.Exception.Status -eq 7) {
                    Write-Host -ForegroundColor Yellow "Access to '$($CertUri)' was denied"
                    Write-Host -BackgroundColor Black -ForegroundColor Cyan "   This is likely because it was blocked by the proxy"
                } else {
                    Write-Warning $_.Exception.Message
                }
            }
        }
    } catch {
        Write-Warning $_.Exception.Message
    }

    if (($CertRequest.ServicePoint.Certificate) -and ($CertRequest.ServicePoint.Certificate.Handle -ne 0)) {
        if (!([String]::IsNullOrEmpty($Owner))) {
            if ($CertRequest.ServicePoint.Certificate.Subject -notlike $Owner) {
                Write-Host -ForegroundColor Red "The '$($CertUri)' appears to be impersonated by another issuer: $($CertRequest.ServicePoint.Certificate.Issuer)"
                Write-Host -BackgroundColor Black -ForegroundColor Cyan "   It may be getting replaced by an upstream proxy or other security layer"
            } else {
                Write-Host -ForegroundColor Green "The certifcate for '$($CertUri)' appears to be valid"
            }
        }
    } else {
        Write-Host -ForegroundColor Red "Unable to get certificate for '$($CertUri)'"
        Write-Host -BackgroundColor Black -ForegroundColor Cyan "   This may mean requests are being intercepted by an upstream proxy or other security layer."
    }
    $CertRequest = $null
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

# Usage: Report-CertValidity <UrlToCheck> [ <UrlForProxy> [ <CertOrganizationToMatch> ] ]
Report-CertValidity "https://signin.connect.aveva.com" "http://100.65.30.65:8888" ""
Report-CertValidity "https://insight.connect.aveva.com" "http://100.65.30.65:8888" "*AVEVA*"
