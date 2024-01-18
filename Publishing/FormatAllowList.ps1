# https://dev-rp-z5wwplvmpt7tu.azurewebsites.net/apis/wwocorefunctions/api/OnlineConfigPush?config=dmzv2
# $allowListUrl = 'https://dev.insight.capdev-connect.aveva.com/apis/wwocorefunctions/api/OnlineConfigPush?config=dmzv2-internal'
# Ctrl-O (options) for internal 
#$allowListUrl = 'https://dev.insight.capdev-connect.aveva.com/apis/wwocorefunctions/api/OnlineConfigPush?config=dmzv2'

# Dump the "Allow List" used by DMZ Secure Link
#
# ---------------------------------------------------
#
# Modified: 18-Jan-2024
# By:       E. Middleton
#
# To enable Powershell scripts use:
#    Set-ExecutionPolicy unrestricted
#
# To disable Powershell scripts use (after using the script):
#    Set-ExecutionPolicy restricted
#

$allowListUrl = 'https://insight.connect.aveva.com/apis/wwocorefunctions/api/OnlineConfigPush?config=dmzv2'

# Output entries for a level in the allow list hierarchy, sorted by reverse domain name
Function Show-Level($prefix, [object]$endpoints) {
    # Add simple hostnames and reverse domain names to each entry so it can be used for sorting
    $endpoints | ForEach-Object {
        $_ | add-member –membertype NoteProperty –name clean -value ($_.host -replace '^\.', '' -replace '\\.', '.' -replace '\$$','' -replace '\^','')
        $rdn = $_.clean.split('.')
        [array]::reverse($rdn) 
        $_ | add-member –membertype NoteProperty –name rdn -value ($rdn -Join '.')
    }

    $last = ""
    $endpoints | Sort-Object -property rdn | ForEach-Object {
      if ($script:allEndpoints -notcontains $_.clean) {
          Write-host $prefix $_.clean
          $script:allEndpoints += $_.clean
      } else {
      if ($last -ne $_.clean) {
              # This entry is listed elsewhere...could be a duplicate, but depends on the placement and this script isn't sophisticated enough to determine that
              Write-host -ForegroundColor Yellow $prefix $_.clean
          } else {
              # This was a duplicate at the same level which should be removed
              Write-host -ForegroundColor Red $prefix $_.clean
          }
      }
      $last = $_.clean
    }
    return $endpoints.Count
}

$entries = 0
$allEndpoints = [System.Collections.ArrayList]@()

# Get the current allow list
$response = Invoke-RestMethod $allowListUrl -Method 'GET' -Headers $headers -Body $body

# Common endpoints used by all services
Write-host "`n General"
$entries = $entries + (Show-Level "`t" $response.endpoints)

# Iterate through each product
$response.products | Sort-Object | ForEach-Object {
    Write-host "`n" $_.friendlyName
    $entries = $entries + (Show-Level "`t" $_.endpoints)
    $_.features | ForEach-Object {
        Write-host "`n`t" $_.friendlyName
        $entries = $entries + (Show-Level "`t`t" $_.endpoints)
        $_.regions | ForEach-Object {
            Write-host "`n`t`t" $_.friendlyName
            $entries = $entries + (Show-Level "`t`t`t" $_.endpoints)
        }
    }
}

# Wrap up
Write-host ''
Write-host 'Count:' $entries 'total /' $allEndpoints.Count 'unique'
