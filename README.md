# Contributing
1. Create a branch for your application.
2. Create a folder for your required script.
3. Create a file for your script with the extension **.ps1**. The script name, will be the application name minus the file extension.
4. Ensure the script is in the following format:
````powershell
<#
    .SYNOPSIS

    .DESCRIPTION
        #description:
        #execution mode:
        #tags:

    .NOTES

#>

begin {
    $scriptName = "integrated-monitoring"

    # Start powershell logging
    $SaveVerbosePreference = $VerbosePreference
    $VerbosePreference = 'continue'
    $VMTime = Get-Date
    $LogTime = $VMTime.ToUniversalTime()

    # Create the directory if it doesn't exist
    if (!(Test-Path -Path "$env:SYSTEMROOT\Temp\NerdioManagerLogs\ScriptedActions\$scriptName")) {
        New-Item -ItemType Directory -Path "$env:SYSTEMROOT\Temp\NerdioManagerLogs\ScriptedActions\$scriptName"
    }

    # start logging
    Start-Transcript -Path "$env:SYSTEMROOT\temp\NerdioManagerLogs\ScriptedActions\$scriptName\ps_log.txt" -Append
    Write-Host "################# New Script Run #################"
    Write-host "Current time (UTC-0): $LogTime"
}

process {

}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
````

- Synopsis: Brief overview of the script.
- Description:
    - #description: This is the description that is visible in the Nerdio MSP application.
    - #execution mode: This is how the script is handed. Possible values are: **Individual**, **IndividualWithRestart** or **Combined**.
    - #tags: Tags for grouping and organising scripts within Nerdio MSP.
- Notes: Any notes for usage.
5. Merge the branch and squash the commits.
