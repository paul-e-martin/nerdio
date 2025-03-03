<#
    .DESCRIPTION
    Language Setup Part 1
#>

begin {
    $primaryLanguage = 'en-GB'
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
    $gitlab_root = "https://gitlab.com/ondemand-engineering"
    $repo_root = "$gitlab_root/windows/windows-language-setup/-/raw/main/language_packs/$os"
    $languagePackUri = "$repo_root/Microsoft-Windows-$type-Language-Pack_x64_$($primaryLanguage.toLower()).cab"

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

    $capabilities = @(
        "Microsoft-Windows-LanguageFeatures-Basic-$($primaryLanguage.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
        "Microsoft-Windows-LanguageFeatures-Handwriting-$($primaryLanguage.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
        "Microsoft-Windows-LanguageFeatures-OCR-$($primaryLanguage.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
        "Microsoft-Windows-LanguageFeatures-Speech-$($primaryLanguage.toLower())-Package~31bf3856ad364e35~amd64~~.cab",
        "Microsoft-Windows-LanguageFeatures-TextToSpeech-$($primaryLanguage.toLower())-Package~31bf3856ad364e35~amd64~~.cab"
    )
    # Windows Capability Download

    # Windows Capability Install

    foreach ($Capability in $Capabilities) {
        $capabilityUri = "$repo_root/$capability"

        Write-Host "Downloading $($Capability.Name)"
        Start-BitsTransfer -Source $capabilityUri -Destination "$env:SYSTEMROOT\Temp\$(Split-Path $capabilityUri -Leaf)"
        Write-Host "$($Capability.Name) downloaded"
        $file = Get-Item -Path "$env:SYSTEMROOT\Temp\$(Split-Path $capabilityUri -Leaf)"
        Unblock-File -Path $file.FullName -ErrorAction SilentlyContinue

        Write-Host "Installing $($Capability.Name)"
        Add-WindowsPackage -Online -PackagePath $file.FullName -NoRestart
        Write-Host "$($Capability.Name) Installed"
    }

    # Set System Language
    Set-WinSystemLocale -SystemLocale $primaryLanguage
    Write-Host "Set system locale"
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
