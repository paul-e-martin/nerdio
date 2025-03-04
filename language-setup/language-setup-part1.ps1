<#
    .SYNOPSIS
        Installs Language Pack and capabilities.
    .DESCRIPTION
        #description: Language Setup Part 1.
        #execution mode: IndividualWithRestart
        #tags: Language

    .NOTES
        This Script will download and install the required language pack and set the system locale.
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

    $additionalLanguages = if (-not [string]::IsNullOrEmpty($SecureVars.additionalLanguages)) {
        $SecureVars.additionalLanguages
    }


    [array]$languages = $primaryLanguage, $secondaryLanguage
    if (!([string]::IsNullOrEmpty($additionalLanguages))) {
        $languages += $additionalLanguages.Split(';')
    }

    # Get OS Name
    $osName = (Get-ComputerInfo).OsName
    $os = if ($osName -match "Server \d+") {
        $matches[0].Replace(" ", "_").tolower()
        $type = "Server"
    }
    elseif ($osName -match "Windows \d+") {
        $matches[0].Replace(" ", "_").tolower()
        $type = "Client"
    }
    else {
        $osName
    }
    $storage_account = "https://mcduksstoracc001.blob.core.windows.net"
    $blob_root = "$storage_account/media/windows/language_packs/$os"

    $scriptName = "language-setup"

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
    # Disable Language Pack Cleanup
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -TaskName "Pre-staged app cleanup"
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\MUI\" -TaskName "LPRemove"
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\LanguageComponentsInstaller" -TaskName "Uninstallation"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International" /v "BlockCleanupOfUnusedPreinstalledLangPacks" /t REG_DWORD /d 1 /f

    foreach ($lang in ($languages | Where-Object { $_ -ne 'en-US' })) {
        if (!(Get-WindowsPackage -Online | Where-Object { $_.ReleaseType -eq "LanguagePack" -and $_.PackageName -like "*LanguagePack*$lang*" })) {

            $languagePackUri = "$blob_root/Microsoft-Windows-$type-Language-Pack_x64_$($lang.toLower()).cab"

            # Language Pack Download
            Write-Host "Downloading language pack"
            Start-BitsTransfer -Source $languagePackUri -Destination "$env:SYSTEMROOT\Temp\$(Split-Path $languagePackUri -Leaf)"
            Write-Host "Language pack downloaded"
            $languagePack = Get-Item -Path "$env:SYSTEMROOT\Temp\$(Split-Path $languagePackUri -Leaf)"
            Unblock-File -Path $languagePack.FullName -ErrorAction SilentlyContinue

            # Install Language Pack
            Write-Host "Installing language pack"
            Add-WindowsPackage -Online -PackagePath $languagePack.FullName -NoRestart
            Write-Host "Language pack installed"

            # Remove Language Pack
            $LanguagePack | Remove-Item -Force
            Write-Host "Removed language pack cab file"
        }

        if (($os -ne "server_2016") -or ($os -ne "server_2019")) {

            $capabilities = @(
                "Microsoft-Windows-LanguageFeatures-Basic-$($lang.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
                "Microsoft-Windows-LanguageFeatures-Handwriting-$($lang.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
                "Microsoft-Windows-LanguageFeatures-OCR-$($lang.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
                "Microsoft-Windows-LanguageFeatures-Speech-$($lang.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
                "Microsoft-Windows-LanguageFeatures-TextToSpeech-$($lang.toLower())-Package~31bf3856ad364e35~amd64~~.cab"
            )

            foreach ($Capability in $Capabilities) {
                if ($Capability = (Get-WindowsCapability -Online | Where-Object { $_.Name -match "$lang" -and $_.Name -match $capability.Split("-")[3] }).State -ne "Installed") {

                    $capabilityUri = "$blob_root/$capability"

                    # Windows Capability Download
                    Write-Host "Downloading $($Capability.Name)"
                    Start-BitsTransfer -Source $capabilityUri -Destination "$env:SYSTEMROOT\Temp\$(Split-Path $capabilityUri -Leaf)"
                    Write-Host "$($Capability.Name) downloaded"
                    $file = Get-Item -Path "$env:SYSTEMROOT\Temp\$(Split-Path $capabilityUri -Leaf)"
                    Unblock-File -Path $file.FullName -ErrorAction SilentlyContinue

                    # Windows Capability Install
                    Write-Host "Installing $($Capability.Name)"
                    Add-WindowsPackage -Online -PackagePath $file.FullName -NoRestart
                    Write-Host "$($Capability.Name) Installed"

                    # Remove file
                    $file | Remove-Item -Force
                }
            }
        }
    }

    # Set System Language
    Set-WinSystemLocale -SystemLocale $lang
    Write-Host "Set system locale"
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
