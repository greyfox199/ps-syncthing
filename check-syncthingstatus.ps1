[cmdletbinding()]
param (
    [Parameter (Mandatory = $true)] [String]$ConfigFilePath
)

#if json config file does not exist, abort process
if (-not(Test-Path -Path $ConfigFilePath -PathType Leaf)) {
    throw "json config file specified at $($ConfigFilePath) does not exist, aborting process"
}
  
#if config file configured is not json format, abort process.
try {
    $PowerShellObject=Get-Content -Path $ConfigFilePath | ConvertFrom-Json
} catch {
    throw "Config file of $($ConfigFilePath) is not a valid json file, aborting process"
}

#if PathToKey secure password file does not exist, abort process
if ($PowerShellObject.Required.PathToKey) {
    if (Test-Path -Path $PowerShellObject.Required.PathToKey -PathType Leaf) {
        $APIKeySecure = Get-Content $PowerShellObject.Required.PathToKey | ConvertTo-SecureString
        $APIKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIKeySecure))
    } else {
        throw "failed to get password fromm $($PowerShellObject.Required.PathToKey), aborting process"
    }
} else {
    throw "PathToKey does not exist in json config file, aborting process"
}

#if BaseURL option does not exist in json, abort process
if ($PowerShellObject.Required.BaseURL) {
    $BaseURL = $PowerShellObject.Required.BaseURL
} else {
    throw "BaseURL does not exist in json config file, aborting process"
}

#if ignorehost option does not exist in json, abort process
if ($PowerShellObject.Required.IgnoreHost) {
    $IgnoreHost = $PowerShellObject.Required.IgnoreHost
} else {
    throw "IgnoreHost does not exist in json config file, aborting process"
}

#if devicesToCheck optoin does not exist in json, abort process
if ($PowerShellObject.Required.devicesToCheck) {
    $devicesToCheck = $PowerShellObject.Required.devicesToCheck
} else {
    throw "devicesToCheck does not exist in json config file, aborting process"
}

#if errorMailSender optoin does not exist in json, abort process
if ($PowerShellObject.Required.errorMailSender) {
    $errorMailSender = $PowerShellObject.Required.errorMailSender
} else {
    throw "errorMailSender does not exist in json config file, aborting process"
}

#if errorMailRecipients option does not exist in json, abort process
if ($PowerShellObject.Required.errorMailRecipients) {
    $errorMailRecipients = $PowerShellObject.Required.errorMailRecipients
} else {
    throw "errorMailRecipients does not exist in json config file, aborting process"
}

#if errorMailTenantID option does not exist in json, abort process
if ($PowerShellObject.Required.errorMailTenantID) {
    $errorMailTenantID = $PowerShellObject.Required.errorMailTenantID
} else {
    throw "errorMailTenantID does not exist in json config file, aborting process"
}

#if errorMailAppID option does not exist in json, abort process
if ($PowerShellObject.Required.errorMailAppID) {
    $errorMailAppID = $PowerShellObject.Required.errorMailAppID
} else {
    throw "errorMailAppID does not exist in json config file, aborting process"
}

#if errorMailSubjectPrefix option does not exist in json, abort process
if ($PowerShellObject.Required.errorMailSubjectPrefix) {
    $errorMailSubjectPrefix = $PowerShellObject.Required.errorMailSubjectPrefix
} else {
    throw "errorMailSubjectPrefix does not exist in json config file, aborting process"
}

#if errorMailPasswordFile option does not exist in json, abort process
if ($PowerShellObject.Required.errorMailPasswordFile) {
    $errorMailPasswordFile = $PowerShellObject.Required.errorMailPasswordFile
} else {
    throw "errorMailPasswordFile does not exist in json config file, aborting process"
}

#if ignoreSSLValidation option does not exist in json, abort process
if ($PowerShellObject.Required.ignoreSSLValidation) {
    $ignoreSSLValidation = $PowerShellObject.Required.ignoreSSLValidation
} else {
    throw "ignoreSSLValidation does not exist in json config file, aborting process"
}

[bool] $authStatus = $false
[bool] $healthStatus = $false
[bool] $blnWriteToLog = $false
[int] $intErrorCount = 0
$arrStrErrors = @()

#clear all errors before starting
$error.Clear()

[uint16] $intDaysToKeepLogFiles = 0
[string] $strServerName = $env:computername

$arrDevicesToCheck = $devicesToCheck.Split(",")

#if path to log directory exists, set logging to true and setup log file
if (Test-Path -Path $PowerShellObject.Optional.logsDirectory -PathType Container) {
    $blnWriteToLog = $true
    [string] $strTimeStamp = $(get-date -f yyyy-MM-dd-hh_mm_ss)
    [string] $strDetailLogFilePath = $PowerShellObject.Optional.logsDirectory + "\syncthing-status-detail-" + $strTimeStamp + ".log"
    $objDetailLogFile = [System.IO.StreamWriter] $strDetailLogFilePath
}

#if days to keep log files directive exists in config file, set configured days to keep log files
if ($PowerShellObject.Optional.daysToKeepLogFiles) {
    try {
        $intDaysToKeepLogFiles = $PowerShellObject.Optional.daysToKeepLogFiles
        Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Using $($PowerShellObject.Optional.daysToKeepLogFiles) value specified in config file for log retention" -LogType "Info" -DisplayInConsole $false
    } catch {
        Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Warning: $($PowerShellObject.Optional.daysToKeepLogFiles) value specified in config file is not valid, defaulting to unlimited log retention" -LogType "Warning"
    }
}

if ($ignoreSSLValidation -eq "true") {
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
} else {
    [System.Net.ServicePointManager]::CertificatePolicy = $null
}

$Headers = @{
      "X-API-KEY" = $APIKey
}

try {
    $Url = "$($BaseURL)/rest/system/ping"
    $pingStatus = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
    if ($pingStatus.Ping -ne "pong") {
        $authStatus = $false
        $arrStrErrors += "Syncthing ping status at $($Url) returned $($pingStatus.Ping)"
        Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: Syncthing ping status at $($Url) returned $($pingStatus.Status), aborting job" -LogType "Error"
    } else {
        $authStatus = $true
    }
} catch {
    $ErrorMessage = $_.Exception.Message
	$line = $_.InvocationInfo.ScriptLineNumber
    $authStatus = $false
	$arrStrErrors += "Failed to do authenticateds ping check at $($Url) with the following error: $ErrorMessage, aborting job"
    Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: Failed to do authenticateds ping check at $($Url) at $($line) with the following error: $ErrorMessage, aborting job" -LogType "Error"
}

if ($authStatus -eq $true) {
    $Url = "$($BaseURL)/rest/stats/device"
    $devicesStats = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get

    $Url = "$($BaseURL)/rest/config/devices"
    $devicesConfig = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get

    $ExpectedVsActualDevices = Compare-Object -ReferenceObject $arrDevicesToCheck -DifferenceObject $devicesConfig.name
    Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Checking for $($arrDevicesToCheck.count) expected devices against those in syncthing at $($BaseURL)" -LogType "Info"
    
    foreach ($ExpectedVsActualDevice in $ExpectedVsActualDevices) {
        if ($ExpectedVsActualDevice.SideIndicator -eq "<=") {
            $arrStrErrors += "$($ExpectedVsActualDevice.InputObject) device was expected, but is not in syncthing device list at $($BaseURL), please investigate"
            Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: $($ExpectedVsActualDevice.InputObject) device was expected, but is not in syncthing device list at $($BaseURL), please investigate" -LogType "Error"
        }
    }

    Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Checking $($devicesConfig.count) devices in syncthing at $($BaseURL)" -LogType "Info"

    foreach ($deviceConfig in $devicesConfig) {
        if ($deviceConfig.name.toLower() -ne $IgnoreHost.toLower()) {
            if ($deviceConfig.paused -eq $true) {
                $arrStrErrors += "$($deviceConfig.name) is paused, plesae investigate"
                Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: $($folderconfig.name) is paused, plesae investigate" -LogType "Error"
            }
            $deviceID = $deviceConfig.deviceID
            $dateLastSeen = $devicesStats.$deviceID.lastSeen
            $now = get-date
            $daysSinceLastSeen = New-TimeSpan -Start $dateLastSeen -End $now
            if ($daysSinceLastSeen.days -gt 4) {
                $arrStrErrors += "$($deviceConfig.name) has not been seen for $($daysSinceLastSeen.days) days, please investigate"
                Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: $($deviceConfig.name) has not been seen for $($daysSinceLastSeen.days) days, please investigate" -LogType "Error"
            } else {
                Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: $($deviceConfig.name) last seen $($daysSinceLastSeen.days) days ago at $($dateLastSeen)" -LogType "Info"
            }
        }
    }

    $Url = "$($BaseURL)/rest/config/folders"
    $foldersConfig = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get

    foreach ($folderConfig in $foldersconfig) {
        if ($folderconfig.paused -eq $true) {
            $arrStrErrors += "$($folderconfig.label) is paused, plesae investigate"
            Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: $($folderconfig.label) is paused, plesae investigate" -LogType "Error"
        }
        $Url = "$($BaseURL)/rest/folder/errors?folder=$($folderconfig.id)"
        $folderErrors = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
        if ($folderErrors.length -gt 0) {
            $arrStrErrors += "There are $($folderErrors), please investigate"
            Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: There are $($folderErrors), please investigate" -LogType "Error"
        }
    }

    #todo
    <#
    $Url = "$($BaseURL)/rest/cluster/pending/devices"
    $pendingDevices = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -ContentType application/json

    $Url = "$($BaseURL)/rest/cluster/pending/folders"
    $pendingFolders = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get

    $Url = "$($BaseURL)/rest/system/error"
    $globalErrors = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
    #>

    #log retention
    if ($intDaysToKeepLogFiles -gt 0) {
        try {
            Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Purging log files older than $($intDaysToKeepLogFiles) days from $($PowerShellObject.Optional.logsDirectory)" -LogType "Info"
            $CurrentDate = Get-Date
            $DatetoDelete = $CurrentDate.AddDays("-$($intDaysToKeepLogFiles)")
            Get-ChildItem "$($PowerShellObject.Optional.logsDirectory)" | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item
        } catch {
            $ErrorMessage = $_.Exception.Message
            $line = $_.InvocationInfo.ScriptLineNumber
            $arrStrErrors += "Failed to purge log files older than $($intDaysToKeepLogFiles) days from $($PowerShellObject.Optional.logsDirectory) with the following error: $ErrorMessage"
            Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Error: Failed to purge log files older than $($intDaysToKeepLogFiles) days from $($PowerShellObject.Optional.logsDirectory) with the following error: $ErrorMessage" -LogType "Error"
        }
    }
}



[int] $intErrorCount = $arrStrErrors.Count

if ($intErrorCount -gt 0) {
    Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Encountered $intErrorCount errors, sending error report email" -LogType "Error"
    #loop through all errors and add them to email body
    foreach ($strErrorElement in $arrStrErrors) {
        $intErrorCounter = $intErrorCounter + 1
        $strEmailBody = $strEmailBody + $intErrorCounter.toString() + ") " + $strErrorElement + "<br>"
    }
    $strEmailBody = $strEmailBody + "<br>Please see $strDetailLogFilePath on $strServerName for more details"

    Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Sending email error report via $($errorMailAppID) app on $($errorMailTenantID) tenant from $($errorMailSender) to $($errorMailRecipients) as specified in config file" -LogType "Info"
    $errorEmailPasswordSecure = Get-Content $errorMailPasswordFile | ConvertTo-SecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($errorEmailPasswordSecure)
    $errorEmailPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Send-GVMailMessage -sender $errorMailSender -TenantID $errorMailTenantID -AppID $errorMailAppID -subject "$($errorMailSubjectPrefix): Encountered $($intErrorCount) errors during process" -body $strEmailBody -ContentType "HTML" -Recipient $errorMailRecipients -ClientSecret $errorEmailPassword
}

Out-GVLogFile -LogFileObject $objDetailLogFile -WriteToLog $blnWriteToLog -LogString "$(get-date) Info: Process Complete" -LogType "Info"

$objDetailLogFile.close()