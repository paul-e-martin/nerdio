<#
    .SYNOPSIS
        Installs GuestAttestation extension
    .DESCRIPTION
        #description: Installs the native Azure "GuestAttestation" Extension on the Azure VM
        #execution mode: Combined
        #tags: Monitoring

    .NOTES
        This Script will install the Microsoft GuestAttestation extension on the Azure VM.
#>

# Set Error action
$errorActionPreference = "Stop"

# Ensure context is using correct subscription
Set-AzContext -SubscriptionId $AzureSubscriptionId

# Variables
$AzVM = Get-AzVM -Name $AzureVMName -ResourceGroupName $AzureResourceGroupName
$PublisherName = "Microsoft.Azure.Security.WindowsAttestation"
$ExtensionName = 'GuestAttestation'
$Type = "GuestAttestation"

# Check if the extension is already installed
$extension = Get-AzVMExtension -ResourceGroupName $AzureResourceGroupName -VMName $AzureVMName -Name $ExtensionName -ErrorAction SilentlyContinue

if ($null -eq $extension) {
    # Get the latest major version
    $version = ((Get-AzVMExtensionImage -Location $AzVM.Location -PublisherName $PublisherName -Type $Type).Version[-1][0..2] -join '')

    #enable the Microsoft Guest Attestation Extension
    $AADExtension = @{
        ResourceGroupName      = $AzVM.ResourceGroupName
        Location               = $AzVM.Location
        VMName                 = $AzureVMName
        Name                   = $ExtensionName
        Publisher              = $PublisherName
        ExtensionType          = $Type
        TypeHandlerVersion     = $version
        EnableAutomaticUpgrade = $true
    }
    Set-AzVMExtension @AADExtension
}
else {
    Write-Output "The $ExtensionName extension is already installed on the VM."
}
