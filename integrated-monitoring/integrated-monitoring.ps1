<#
    .SYNOPSIS
        Installs GuestAttestation extension
    .DESCRIPTION
        #description: Installs the native Azure "GuestAttestation" Extension on the Azure VM
        #execution mode: IndividualWithRestart
        #tags: Monitoring

    .NOTES
        This Script will install the Microsoft GuestAttestation extension on the Azure VM.
#>

begin {
    # Set Error action
    $errorActionPreference = "Stop"

    # Ensure context is using correct subscription
    Set-AzContext -SubscriptionId $AzureSubscriptionId

    # Variables
    $AzVM = Get-AzVM -Name $AzureVMName -ResourceGroupName $AzureResourceGroupName
    $PublisherName = "Microsoft.Azure.Security.WindowsAttestation"
    $name = 'GuestAttestation'
    $Type = "GuestAttestation"

    # Get the latest major version
    $version = ((Get-AzVMExtensionImage -Location $AzVM.Location -PublisherName $PublisherName -Type $Type).Version[-1][0..2] -join '')
}

process {
    #enable the Microsoft Guest Attestation Extension
    $AADExtension = @{
        ResourceGroupName      = $AzVM.ResourceGroupName
        Location               = $AzVM.Location
        VMName                 = $AzureVMName
        Name                   = $name
        Publisher              = $PublisherName
        ExtensionType          = $Type
        TypeHandlerVersion     = $version
        EnableAutomaticUpgrade = $true
    }
    Set-AzVMExtension @AADExtension
}
