<# 
==============================================================

    Delete a tag programmatically from AVEVA Insight

==============================================================

This assumes the source which created the tag has stopped sending tag values--if the source
is still sending data, the tag will be recreated.

Modified: 12-Feb-2025
By:       E. Middleton

 To enable Powershell scripts use:
    Set-ExecutionPolicy unrestricted

 To disable Powershell scripts use (after using the script):
    Set-ExecutionPolicy restricted

============================================================== 
#>

# Update this for other regions
$BaseUrl= 'https://online.wonderware.com/apis/Historian/v2/'

# Login to Insight and open the browser's DevTools (F12) and select the "Network" tab. Copy the "authorization" header from one of the requests
# and replace the string value below
$headers = @{
    Authorization="Bearer eyJhbGciOiJ...."
}

# Note: You must escape any embedded $ characters in the URL with a backtick `
$QueryUrl = $BaseUrl + "Tags"

# As written, this deletes a single tag using it's FQN, but you can include a list in the "FQN" array in JSON format
$toDelete = 'MyDataSource.TheTagToDelete'
$jsonBody = '{"delete":{"FQN":["' + $toDelete + '"]}}'

$Response = Invoke-WebRequest -Method 'POST' -Headers $headers -Uri $QueryUrl -ContentType "application/json" -Body $jsonBody

