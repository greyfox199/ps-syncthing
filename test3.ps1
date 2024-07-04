write-host "before invoke"
$Url = "https://atlantis:8384/rest/noauth/health"
$status = Invoke-RestMethod -Uri $Url -Method Get
write-host $status.status
write-host "after invoke"