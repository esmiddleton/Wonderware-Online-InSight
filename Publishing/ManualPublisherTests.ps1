#
# A concise set of manual tests related to connectivity to AVEVA Insight
# For more complete tests, see separate "PublisherNetworkDiagnostics.ps1" script
# Use with Powershell 5.1+
#

$ProxyAddress = "192.168.200.90"  # Replace with the IP address of your proxy
$ProxyPort = 8888                 # Repalce with the port your proxy listens on

$InsightHost = "online.wonderware.com"

# Test a TCP connection to the proxy--failure likely due to a firewall blocking it
Test-NetConnection $ProxyAddress -Port $ProxyPort -InformationLevel "Detailed"

# Test an HTTP request to Insight using the proxy--failure likely due to problem with next proxy
(Invoke-WebRequest -Uri "http://$($InsightHost)" -Proxy "http://$($ProxyAddress):$($ProxyPort)").StatusDescription

# Test an HTTPS (secure) request to Insight using the proxy--failure likely due to not supporting TLS 1.2
(Invoke-WebRequest -Uri "https://$($InsightHost)" -Proxy "http://$($ProxyAddress):$($ProxyPort)").StatusDescription

# Test an HTTPS (secure) request using the default user proxy ("Internet Options")
(Invoke-WebRequest -Uri "https://$($InsightHost)").StatusDescription

# Test an unauthorized site via DMZ Secure Link--"OK" means not using DMZ Secure Link
# Correctly blocked should cause an exception with "Only web sites which are part of AVEVA Insight may be accessed via the Secure Link proxy."
(Invoke-WebRequest -Uri "http://www.apple.com" -Proxy "http://$($ProxyAddress):$($ProxyPort)").StatusDescription

# List the ciphers and encryption protocols supported by this client application (Powershell)
(Invoke-WebRequest -Uri https://howsmyssl.com/a/check -Proxy "http://$($ProxyAddress):$($ProxyPort)").Content -Split ","
