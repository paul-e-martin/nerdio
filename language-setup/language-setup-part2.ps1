<#
    .SYNOPSIS
        Sets region and locale settings.
    .DESCRIPTION
        #description: Language Setup Part 2.
        #execution mode: IndividualWithRestart
        #tags: Language

    .NOTES
        This Script will set the required culture, override, location, timezone, and copy settings to system and new accounts.
#>
begin {
    $primaryLanguage = if (-not [string]::IsNullOrEmpty($SecureVars.primaryLanguage)) {
        $SecureVars.primaryLanguage
    }
    else {
        $InheritedVars.primaryLanguage
    }

    $secondaryLanguage = if (-not [string]::IsNullOrEmpty($SecureVars.secondaryLanguage)) {
        $SecureVars.secondaryLanguage
    }
    else {
        $InheritedVars.secondaryLanguage
    }

    $languageProperties = @{
        "en-GB" = @{
            InputCode = "0809:00000809"
            GeoID     = "242"
            TimeZone  = "GMT Standard Time"
        }
        "en-US" = @{
            InputCode = "0409:00000409"
            GeoID     = "244"
            TimeZone  = "Central Daylight Time"
        }
        "fr-FR" = @{
            InputCode = "040C:0000040C"
            GeoID     = "84"
            TimeZone  = "Central European Summer Time"
        }
        "de-DE" = @{
            InputCode = "0407:00000407"
            GeoID     = "94"
            TimeZone  = "Central European Summer Time"
        }
        "it-IT" = @{
            InputCode = "0410:00000410"
            GeoID     = "118"
            TimeZone  = "Central European Summer Time"
        }
        "es-ES" = @{
            InputCode = "0C0A:0000040A"
            GeoID     = "217"
            TimeZone  = "Central European Summer Time"
        }
    }

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
    Set-WinHomeLocation -GeoId $languageProperties[$primaryLanguage].GeoID
    Write-Host "Location set to $($languageProperties[$primaryLanguage].GeoID)"

    # Set Input Method
    $NewLanguageList = New-WinUserLanguageList -Language "$primaryLanguage"
    $NewLanguageList.Add([Microsoft.InternationalSettings.Commands.WinUserLanguage]::new("$secondaryLanguage"))
    $NewLanguageList[1].InputMethodTips.Clear()
    $NewLanguageList[1].InputMethodTips.Add("$($languageProperties[$primaryLanguage].InputCode)")
    $NewLanguageList[1].InputMethodTips.Add("$($languageProperties[$secondaryLanguage].InputCode)")
    Set-WinUserLanguageList -LanguageList $NewLanguageList -Force
    Write-Host "Keyboard input set"

    # Set Timezone
    Set-TimeZone -Name $languageProperties[$primaryLanguage].TimeZone
    Write-Host "Timezone set to $($languageProperties[$primaryLanguage].TimeZone)"

    # Create XML Content
    $XML = @"
<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">

<!-- user list -->
<gs:UserList>
<gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/>
</gs:UserList>

<!-- GeoID -->
<gs:LocationPreferences>
<gs:GeoID Value='$($languageProperties[$primaryLanguage].GeoID)'/>
</gs:LocationPreferences>

<gs:MUILanguagePreferences>
<gs:MUILanguage Value='$primaryLanguage'/>
<gs:MUIFallback Value='$secondaryLanguage'/>
</gs:MUILanguagePreferences>

<!-- system locale -->
<gs:SystemLocale Name='$primaryLanguage'/>

<!-- input preferences -->
<gs:InputPreferences>
<gs:InputLanguageID Action="add" ID='$($languageProperties[$primaryLanguage].InputCode)' Default="true"/>
<gs:InputLanguageID Action="add" ID='$($languageProperties[$secondaryLanguage].InputCode)'/>
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
