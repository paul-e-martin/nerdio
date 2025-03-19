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
    $profFileServer = "$($SecureVars.fslogixProfSAName).file.core.windows.net"
    $profUser = "localhost\$($SecureVars.fslogixProfSAName)"
    $profSecret = "$($SecureVars.fslogixProfSAKey)"

    # odfc
    $odfcFileServer = "$($SecureVars.fslogixODFCSAName).file.core.windows.net"
    $odfcUser = "localhost\$($SecureVars.fslogixODFCSAName)"
    $odfcSecret = "$($SecureVars.fslogixODFCSAKey)"

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
    # Check if the key exists
    if (-not(Test-Path "HKLM:\Software\Policies\Microsoft\AzureADAccount")) {
        # Create the key if it doesn't exist
        New-Item -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Force
    }

    # Add or modify the property
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Name "LoadCredKeyFromProfile" -Value 1 -Type DWord -Force

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
