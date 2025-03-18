<#
    .SYNOPSIS
        Configures the AVD Host to use the storage account key to access the storage account on behalf of the users..
    .DESCRIPTION
        #description: FSLogix Entra ID storage account key.
        #execution mode: Combined
        #tags: Language

    .NOTES
        This Script will add the credentials for the storage account into the Windows Credential Manager.
#>

begin {
    # profile
    $profFileServer = "$($SecureVars.'fslogix-prof-sa-name').file.core.windows.net"
    $profUser = "localhost\$($SecureVars.'fslogix-prof-sa-name')"
    $profSecret = "$($SecureVars.'fslogix-prof-sa-key')"

    # odfc
    $odfcFileServer = "$($SecureVars.'fslogix-odfc-sa-name').file.core.windows.net"
    $odfcUser = "localhost\$($SecureVars.'fslogix-odfc-sa-name')"
    $odfcSecret = "$($SecureVars.'fslogix-odfc-sa-key')"

    $scriptName = "fslogix-entra-id"

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
    # profile
    try {
        cmd.exe /c "cmdkey.exe /add:$profFileServer /user:$($profUser) /pass:$($profSecret)"
        Write-Host "Configured $profFileServer credentials"
    }
    catch {
        Write-Host "Failed to configure $profFileServer credentials: $_"
    }

    # odfc
    try {
        cmd.exe /c "cmdkey.exe /add:$odfcFileServer /user:$($odfcUser) /pass:$($odfcSecret)"
        Write-Host "Configured $odfcFileServer credentials"
    }
    catch {
        Write-Host "Failed to configure $odfcFileServer credentials: $_"
    }
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
