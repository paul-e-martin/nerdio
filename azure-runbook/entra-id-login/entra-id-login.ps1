<#
    .SYNOPSIS
        Installs Entra ID Login extension
    .DESCRIPTION
        #description: Installs the native Azure "ADDLogin" Extension on the Azure VM
        #execution mode: Combined
        #tags: EntraID

    .NOTES
        This Script will install the Microsoft AADLogin extension on the Azure VM.
#>

begin {
    $scriptName = "entra-id-login"

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

    # Set Error action
    $errorActionPreference = "Stop"

    # Ensure context is using correct subscription
    Set-AzContext -SubscriptionId $AzureSubscriptionId

    # Variables
    $AzVM = Get-AzVM -Name $AzureVMName -ResourceGroupName $AzureResourceGroupName
    $PublisherName = "Microsoft.Azure.ActiveDirectory"
    $Type = "AADLoginForWindows"
    $name = 'AADLogin'

    # Get the latest major version
    $version = ((Get-AzVMExtensionImage -Location $AzVM.Location -PublisherName $PublisherName -Type $Type).Version[-1][0..2] -join '')
}

process {
    #enable the Microsoft Active Directory Login Extension
    $AADExtension = @{
        ResourceGroupName  = $AzVM.ResourceGroupName
        Location           = $AzVM.Location
        VMName             = $AzureVMName
        Name               = $name
        Publisher          = $PublisherName
        ExtensionType      = $Type
        TypeHandlerVersion = $version
    }
    Set-AzVMExtension @AADExtension
}

end {
    # End Logging
    Stop-Transcript
    $VerbosePreference = $SaveVerbosePreference
}
