<#
    .DESCRIPTION
    Windows Hardening Script
#>

begin {
    $pw = $SecureVars.windowsPassword

    $scriptName = "windows-base"

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
    # Get Operating System Product Name
    $OS = (Get-CimInstance -ClassName 'Win32_OperatingSystem').Name.Split('|')[0]

    # Rename Built-in Administrator Account
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }
        Rename-LocalUser -SID $adminAccount.Sid.Value -NewName "_Administrator"
        Write-Host "Renamed Administrator account"

        # Disable Built-in Administrator Account
        Disable-LocalUser -SID $adminAccount.Sid.Value
        Write-Host "Disabled SID500 Administrator account"

        # Remove Built-in Admin Profile
        Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -like "$($adminAccount.Sid.Value)" } | Remove-CimInstance
        Write-Host "Removed SID500 Administrator account profile"

    # Create New Admin
    New-LocalUser $adminAccount.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -Description "Local Administrator" -PasswordNeverExpires
    Add-LocalGroupMember -Group 'Administrators' -Member $adminAccount.Name
    Remove-LocalGroupMember -Group 'Users' -Member $adminAccount.Name -ErrorAction SilentlyContinue
    Write-Host "Created new local Administrator account"

    # Rename Guest Account
    $guestAccount = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' }
    if ($guestAccount.Name -eq "Guest") {
        Rename-LocalUser -SID $guestAccount.Sid.Value -NewName "_Guest"
        Write-Host "Renamed Guest account"
    }

    # Disable Guest Account
    Disable-LocalUser -SID $guestAccount.Sid.Value
    Write-Host "Disabled Guest account"

    # Set time source
    $Computer = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem
    if ($Computer.Domain -ne "WORKGROUP") {
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\' -Name "Type" -Value 'NT5DS' -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider\' -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
        Get-Service -Name "W32Time" | Restart-Service
        Write-Host "Set Time Source to NT5DS"
    }

    # Expand OS Partition to Max
    $Disk = Get-Disk | Where-Object IsSystem -eq $True
    $Partition = $Disk | Get-Partition | Where-Object IsBoot -eq $True
    $MaxSize = (Get-PartitionSupportedSize -DiskNumber $Disk.Number -PartitionNumber $Partition.PartitionNumber).SizeMax
    Resize-Partition -DiskNumber $Disk.Number -PartitionNumber $Partition.PartitionNumber -Size $MaxSize -ErrorAction SilentlyContinue
    Write-Host "Expanded System Partition to $MaxSize"

    # Change Optical Drive to Z:
    $Optical = Get-CimInstance -Class Win32_CDROMDrive | Select-Object -ExpandProperty Drive
    if (!($null -eq $Optical) -and !($Optical -eq 'Z:')) {
        Set-CimInstance -InputObject ( Get-CimInstance -Class Win32_volume -Filter "DriveLetter = '$Optical'" ) -Arguments @{DriveLetter = 'Z:' }
        Write-Host "Set Optical Drive to Z:"
    }

    # Enable Crash Dumps
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\' -Name 'CrashDumpEnabled' -Value 3 -ErrorAction SilentlyContinue
    Write-Host "Enabled Crash Dumps"

    # Set Advanced Audit Policy
    $auditPolList = @(
        "System"
        "Logon/Logoff"
        "Object Access"
        "Privilege Use"
        "Detailed Tracking"
        "Account Management"
        "DS Access"
        "Account Logon"
    )
    foreach ($policy in $auditPolList) {
        auditpol /set /category:$policy /failure:enable /success:enable
        Write-Host "Configured Advanced Audit Policy: $policy"
    }

    # Reregister performance counters
    Start-Process C:\Windows\System32\lodctr.exe -ArgumentList '/q' -NoNewWindow -Wait
    Write-Host "Reregistered performance counters"

    # Set Eventlog Sizes
    Limit-EventLog -LogName Application -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Limit-EventLog -LogName Security -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Limit-EventLog -LogName System -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Write-Host "Set EventLog Size"

    # Enable Ping rules
    Enable-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -Name "FPS-ICMP6-ERQ-In" -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -Name "FPS-ICMP4-ERQ-Out" -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -Name "FPS-ICMP6-ERQ-Out" -ErrorAction SilentlyContinue

    # Enable WMI rules
    Enable-NetFirewallRule -Name "WMI-RPCSS-In-TCP" -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -Name "WMI-WINMGMT-In-TCP" -ErrorAction SilentlyContinue
    Write-Host "Configured Windows Firewall to allow Ping and WMI"

    # Disable Windows Powershell V2
    if ($OS -like "*Server*") {
        Remove-WindowsFeature -Name PowerShell-V2 -ErrorAction SilentlyContinue
    }
    else {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    }
    Write-Host "Uninstalled PowerShell V2"

    # Enable Telnet Client
    if ($OS -like "*Server*") {
        Install-WindowsFeature -Name Telnet-Client -ErrorAction SilentlyContinue
    }
    else {
        Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
    }
    Write-Host "Installed Telnet Client"

    # Enable Remote Powershell
    Enable-PSRemoting -SkipNetworkProfileCheck -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Enabled PowerShell remoting"

    # Disable ieESC
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Disabled ieESC"

    # Configure TLS/SSL
    # TLS 1.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.0' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Name 'Client' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Name 'Server' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    # TLS 1.1
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.1' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Name 'Client' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Name 'Server' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    # TLS 1.2
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.2' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -Name 'Client' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -Name 'Server' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue

    # SSL 2.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'SSL 2.0' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0' -Name 'Client' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0' -Name 'Server' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    #SSL 3.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'SSL 3.0' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0' -Name 'Client' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0' -Name 'Server' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    # dotnet 2 SSL
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\' -Name 'v2.0.50727' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\' -Name 'v2.0.50727' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    # dotnet 4 SSL
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\' -Name 'v4.0.30319' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\' -Name 'v4.0.30319' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

    Write-Host "Configured TLS/SSL"

    # Allow IE file downloads
    Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\' -Name '1803' -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Allow IE File Downloads"

    # Disable Protected Mode Banner in IE
    Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'NoProtectedModeBanner' -Value 1 -ErrorAction SilentlyContinue
    Write-Host "Disabled IE Protected Mode Banner"

    # Disable IE First Run Wizard:
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'Internet Explorer' -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Value 1  -ErrorAction SilentlyContinue
    Write-Host "Disabled IE First Run Wizard"

    # Disable WAC Prompt
    if ($OS -like "*Server*") {
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager' -Name 'DoNotPopWACConsoleAtSMLaunch' -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Disabled WAC Prompt"
    }

    # Set VM to High Perf scheme
    POWERCFG -SetActive '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    Write-Host "Set VM to High Performance"

    # Disable Hard Disk Timeouts
    POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    Write-Host "Disabled Hard Disk Timeouts"

    # Disable Hibernate
    POWERCFG -h off
    Write-Host "Disabled Hibernate"

    # Disable New Network Dialog
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' -ErrorAction SilentlyContinue
    Write-Host "Disabled New Network Dialog"

    # Disable LLMNR
    New-Item -Path 'HKLM:\SOFTWARE\policies\Microsoft\Windows NT\' -Name 'DNSClient' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -PropertyType DWord -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Disabled LLMNR"

    # Disable NetBIOS
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $key | ForEach-Object { Set-ItemProperty -Path "$key\$($_.PSChildName)" -Name NetbiosOptions -Value 2 }
    Write-Host "Disabled NetBIOS"

    # Enable Task Manager Disk Performance Counters
    diskperf -Y
    Write-Host "Enable Task Manager Disk Performance Counters"

    # Modify SMB defaults
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart
    Write-Host "Disabled SMB1"

    # SMB Modifications for performance:
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -PropertyType DWord -Value '8000' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -PropertyType DWord -Value '1000' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundCacheEntriesMax' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -PropertyType DWord -Value '8000' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue

    # Enable SMB signing
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters' -Name "RequireSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "RequireSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters' -Name "EnableSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "EnableSecuritySignature" -Value 1 -ErrorAction SilentlyContinue

    # Disable Autoplay
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue
    Write-Host "Disabled Autoplay"

    # Disable Null Session Access
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "RestrictNullSessAccess" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RestrictAnonymous" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RestrictAnonymousSAM" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "EveryoneIncludesAnonymous" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Disabled Null Sessions"

    # Remove (Almost All) Inbox UWP Apps:
    if ($OS -notlike "*Server*") {
        # Get list of Provisioned Start Screen Apps
        $Apps = Get-ProvisionedAppxPackage -Online

        # Disable "Consumer Features" (aka downloading apps from the internet automatically)
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue
        # Disable the "how to use Windows" contextual popups
        New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue

        $appsToRemove = @('Clipchamp.Clipchamp',
            'Microsoft.3DBuilder',
            'Microsoft.549981C3F5F10',
            'Microsoft.BingFinance',
            'Microsoft.BingNews',
            'Microsoft.BingSearch',
            'Microsoft.BingSports',
            'Microsoft.BingWeather',
            'Microsoft.CommsPhone',
            'Microsoft.ConnectivityStore',
            'Microsoft.GamingApp',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.Messaging',
            'Microsoft.Microsoft.XboxIdentityProvider',
            'Microsoft.Microsoft3DViewer',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MixedReality.Portal',
            'Microsoft.Office.OneNote',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.People',
            'Microsoft.PowerAutomateDesktop',
            'Microsoft.SkypeApp',
            'Microsoft.Todos',
            'Microsoft.Wallet',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxApp',
            'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.YourPhone',
            'Microsoft.ZuneMusic',
            'Microsoft.ZuneVideo'
        )

        # Remove Windows Store Apps
        ForEach ($App in $Apps) {
            If ($App.DisplayName -in $appsToRemove) {
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName
                Remove-AppxPackage -Package $App.PackageName
                Write-Host "Removed $($App.DisplayName)"
            }
        }
    }
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
