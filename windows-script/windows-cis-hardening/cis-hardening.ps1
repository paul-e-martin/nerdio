<#
    .SYNOPSIS
        Hardens the virtual machine to CIS standards.
    .DESCRIPTION
        #description: Windows CIS Hardening.
        #execution mode: IndividualWithRestart
        #tags: CIS

    .NOTES
        This Script will harden the virtual machine with CIS controls.
#>

begin {
    # Install required PowerShell module
    Install-PackageProvider -Name 'NuGet' -Scope CurrentUser -Confirm:$False -Force | Out-Null
    Install-Module -Name 'Carbon' -Scope CurrentUser -Confirm:$False -Force | Out-Null
    Install-Module -Name 'AuditPolicy' -Scope CurrentUser -Confirm:$False -Force | Out-Null

    function Set-Registry {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $registryPath,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $registryProperty,

            [Parameter(Mandatory = $true)]
            [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')]
            [string] $registryType,

            [Parameter(Mandatory = $true)]
            [string] $registryValue
        )

        begin {
            $type = 'Registry'
        }

        process {
            Write-Host "Configuring ControlID: $controlID"

            if ($null -ne (Get-ItemProperty -Path $registryPath -Name $registryProperty -ErrorAction SilentlyContinue)) {
                $value = Get-ItemPropertyValue -Path $registryPath -Name $registryProperty
            }
            else {
                $value = 'N/A'
            }

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = $registryPath
                "RegistryProperty"    = $registryProperty
                "RegistryType"        = $registryType
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($registryValue -eq 'N/A') {
                    if ($PSCmdlet.ShouldProcess("$($registryPath)", "Remove registry property: $registryProperty")) {
                        Remove-ItemProperty -Path $registryPath -Name $registryProperty
                    }
                }
                elseif ($registryValue -eq 'ValueNeedsToBeCleared') {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Clear registry property: $registryProperty")) {
                        Clear-ItemProperty -Path $registryPath -Name $registryProperty
                    }
                }
                else {
                    if ($PSCmdlet.ShouldProcess($registryPath, "New registry property: $registryProperty of value: $registryValue and type: $registryType")) {
                        If (-not (Test-Path -Path $registryPath)) {
                            New-Item -Path $registryPath -Force | Out-Null
                        }
                        New-ItemProperty -Path $registryPath -Name $registryProperty -Value $registryValue -PropertyType $registryType -Force | Out-Null
                    }
                }
                if ($registryValue -eq 'ValueNeedsToBeCleared') {
                    $registryValue = ''
                }
                $obj.NewValue = $registryValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-NetAccounts {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateSet('MINPWLEN', 'MINPWAGE', 'uniquepw', 'lockoutduration', 'lockoutthreshold', 'lockoutwindow')]
            [string] $netAccountsType,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $netAccountsValue
        )

        begin {
            $type = 'NetAccounts'
        }

        process {
            Write-Host "Configuring ControlID: $controlID"

            switch ($netAccountsType) {
                'MINPWLEN' { $index = 3 }
                'MINPWAGE' { $index = 1 }
                'uniquepw' { $index = 4 }
                'lockoutduration' { $index = 6 }
                'lockoutthreshold' { $index = 5 }
                'lockoutwindow' { $index = 7 }
            }

            $value = (net accounts)[$index].split(':')[1].trim()

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = $netAccountsType
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($netAccountsType)", "Set: $netAccountsValue")) {
                    net accounts /$($netAccountsType):$netAccountsValue
                }
                $obj.NewValue = $netAccountsValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-CPrivilege {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $identity,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $privilege,

            [Parameter(Mandatory = $true)]
            [ValidateSet('True', 'False')]
            [string] $requiredValue
        )

        begin {
            $type = 'CPrivilege'
        }

        process {
            Write-Host "Configuring ControlID: $controlID"

            $value = Test-CPrivilege -Identity $identity -Privilege $privilege

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = $identity
                "CPrivilegePrivilege" = $privilege
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($requiredValue -eq 'True') {
                    if ($PSCmdlet.ShouldProcess("$($identity)", "Grant $privilege")) {
                        Grant-CPrivilege -Identity $identity -Privilege $privilege
                    }
                }
                if ($requiredValue -eq 'False') {
                    if ($PSCmdlet.ShouldProcess("$($identity)", "Revoke $privilege")) {
                        Revoke-CPrivilege -Identity $identity -Privilege $privilege
                    }
                }
                $obj.NewValue = $requiredValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-AuditPol {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $auditPolCategory,

            [Parameter(Mandatory = $true)]
            [ValidateSet('SuccessAndFailure', 'Success', 'Failure', 'NotConfigured')]
            [string] $auditPolValue
        )

        begin {
            $type = 'AuditPol'
        }

        process {
            Write-Host "Configuring ControlID: $controlID"

            $value = (Get-SystemAuditPolicy -Policy $auditPolCategory).Value

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = $auditPolCategory
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($auditPolCategory)", "Set $auditPolValue")) {
                    Set-SystemAuditPolicy -Policy $auditPolCategory -Value $auditPolValue
                }
                $obj.NewValue = $auditPolValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Rename-Account {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $account,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $newName
        )

        begin {
            $type = 'Account'
        }

        process {
            Write-Host "Configuring ControlID: $controlID"

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $account
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($account)", "Rename $newName")) {
                    Rename-LocalUser -Name $account -NewName $newName
                }
                $obj.NewValue = $newName
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    $level = if (-not [string]::IsNullOrEmpty($SecureVars.windowsCISLevel)) {
        $SecureVars.windowsCISLevel
    }
    else {
        $InheritedVars.windowsCISLevel
    }

    $controlsCSV = if (-not [string]::IsNullOrEmpty($SecureVars.windowsCISControls)) {
        $SecureVars.windowsCISControls
    }
    else {
        $InheritedVars.windowsCISControls
    }

    $scriptName = "windows-cis-hardening"

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

    if ($controlsCSV -match '^(http|https)://') {
        try {
            $fileName = 'controls.csv'
            $downloadPath = Join-Path -Path (Get-Location).Path -ChildPath $fileName
            Invoke-WebRequest -Uri $controlsCSV -OutFile $fileName
            if (Test-Path $downloadPath -PathType 'Leaf') {
                $controlsCSV = $downloadPath
            }
            else {
                throw "Failed to download the file from URL: $controlsCSV"
            }
        }
        catch {
            throw "URL is not accessible or the file could not be downloaded: $controlsCSV"
        }
    }

    [array]$global:results = @()
}

process {

    # import controls based on environment
    $controls = Import-Csv -Path $controlsCSV | Where-Object { ($_.ENABLED -eq $true) }

    # Registry section
    foreach ($control in ($controls | Where-Object { ($_.Type -eq "Registry") -and ([int]$_.Level -le $level) })) {
        if ($control.RegistryPath -like "HKEY_USERS*") {
            foreach ($user in (Get-LocalUser)) {
                $sid = (Get-LocalUser -Name $user).SID.value
                If (Test-Path "Registry::HKEY_USERS\$sid") {
                    Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath -replace '(?i).Default', $sid)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $control.Value
                }
            }
        }
        Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $control.Value
    }

    # NetAccounts section
    foreach ($control in ($controls | Where-Object { ($_.Type -eq "NetAccounts") -and ([int]$_.Level -le $level) })) {
        Set-NetAccounts -controlID $control.ControlID -netAccountsType $control.netAccountsType -netAccountsValue $control.Value
    }

    # CPrivilege section
    foreach ($control in ($controls | Where-Object { ($_.Type -eq "CPrivilege") -and ([int]$_.Level -le $level) })) {
        Set-CPrivilege -controlID $control.ControlID -identity $control.CPrivilegeIdentity -privilege $control.CPrivilegePrivilege -requiredValue $control.Value
    }

    # Audit Policy section
    foreach ($control in ($controls | Where-Object { ($_.Type -eq "AuditPol") -and ([int]$_.Level -le $level) })) {
        Set-AuditPol -controlID $control.ControlID -auditPolCategory $control.AuditPolCategory -auditPolValue $control.Value
    }

    # Rename accounts section
    foreach ($control in ($controls | Where-Object { ($_.Type -eq "Account") -and ([int]$_.Level -le $level) })) {

        if ($control.ControlID -eq '8366') {
            if (($user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' }).Name -eq "Guest") {
                Rename-Account -controlID $control.ControlID -account $user.Name -newName $control.Value
            }
        }

        if ($control.ControlID -eq '8367') {
            if (($user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Name -eq "Administrator") {
                Rename-Account -controlID $control.ControlID -account $user.Name -newName $control.Value
            }
        }
    }
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
