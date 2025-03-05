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

# Ensure context is using correct subscription
Set-AzContext -SubscriptionId $AzureSubscriptionId

# Variables
$AzVM = Get-AzVM -Name $AzureVMName -ResourceGroupName $AzureResourceGroupName
$PublisherName = "Microsoft.Azure.ActiveDirectory"
$Type = "AADLoginForWindows"
$name = 'AADLogin'

# Get the latest major version
$version = ((Get-AzVMExtensionImage -Location $AzVM.Location -PublisherName $PublisherName -Type $Type).Version[-1][0..2] -join '')

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
