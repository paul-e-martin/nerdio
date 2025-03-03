<#
    .DESCRIPTION
    Language Setup Part 2
#>

begin {
    $primaryLanguage = 'en-GB'
    $secondaryLanguage = 'en-US'
    $primaryInputCode = '0809:00000809'
    $secondaryInputCode = '0409:00000409'
    $primaryGeoID = '242'
    $timeZone = 'GMT Standard Time'

    # Start powershell logging
    $SaveVerbosePreference = $VerbosePreference
    $VerbosePreference = 'continue'
    $VMTime = Get-Date
    $LogTime = $VMTime.ToUniversalTime()

    # Create the directory if it doesn't exist
    if (!(Test-Path -Path "$env:SYSTEMROOT\Temp\NerdioManagerLogs\ScriptedActions\languageSetup")) {
        New-Item -ItemType Directory -Path "$env:SYSTEMROOT\Temp\NerdioManagerLogs\ScriptedActions\languageSetup"
    }

    # start logging
    Start-Transcript -Path "$env:SYSTEMROOT\temp\NerdioManagerLogs\ScriptedActions\languageSetup\ps_log.txt" -Append
    Write-Host "################# New Script Run #################"
    Write-host "Current time (UTC-0): $LogTime"
}

process {
    # Set languages/culture
    Set-Culture -CultureInfo $primaryLanguage
    Write-Host "Culture set to $primaryLanguage"

    # Set UI Language
    Set-WinUILanguageOverride -Language $primaryLanguage
    Write-Host "UI Language set to $primaryLanguage"

    # Set Location
    Set-WinHomeLocation -GeoId $primaryGeoID
    Write-Host "Location set to $primaryGeoID"

    # Set Input Method
    $NewLanguageList = New-WinUserLanguageList -Language "$primaryLanguage"
    $NewLanguageList.Add([Microsoft.InternationalSettings.Commands.WinUserLanguage]::new("$secondaryLanguage"))
    $NewLanguageList[1].InputMethodTips.Clear()
    $NewLanguageList[1].InputMethodTips.Add("$primaryInputCode")
    $NewLanguageList[1].InputMethodTips.Add("$secondaryInputCode")
    Set-WinUserLanguageList -LanguageList $NewLanguageList -Force
    Write-Host "Keyboard input set"

    # Set Timezone
    Set-TimeZone -Name "$timeZone"
    Write-Host "Timezone set to $timeZone"

    # Create XML Content
    $XML = @"
<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">

<!-- user list -->
<gs:UserList>
<gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/>
</gs:UserList>

<!-- GeoID -->
<gs:LocationPreferences>
<gs:GeoID Value='$primaryGeoID'/>
</gs:LocationPreferences>

<gs:MUILanguagePreferences>
<gs:MUILanguage Value='$primaryLanguage'/>
<gs:MUIFallback Value='$secondaryLanguage'/>
</gs:MUILanguagePreferences>

<!-- system locale -->
<gs:SystemLocale Name='$primaryLanguage'/>

<!-- input preferences -->
<gs:InputPreferences>
<gs:InputLanguageID Action="add" ID='$primaryInputCode' Default="true"/>
<gs:InputLanguageID Action="add" ID='$secondaryInputCode'/>
</gs:InputPreferences>

<!-- user locale -->
<gs:UserLocale>
<gs:Locale Name='$primaryLanguage' SetAsCurrent="true" ResetAllSettings="false"/>
</gs:UserLocale>
</gs:GlobalizationServices>
"@

    # Create XML
    $File = New-Item -Path "$env:SYSTEMROOT\Temp\" -Name "$primaryLanguage.xml" -ItemType File -Value $XML -Force

    # Copy to System and welcome screen
    Start-Process -FilePath "$env:SYSTEMROOT\System32\Control.exe" -ArgumentList "intl.cpl, , /f:""$($File.Fullname)""" -NoNewWindow -PassThru -Wait | Out-Null
    Write-Host "Set language for new users, system and welcome screen"

    # Remove XML
    $File | Remove-Item -Force
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
