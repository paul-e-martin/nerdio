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
        #Write-Log -Object "Hardening" -Message "Removed $($App.DisplayName)" -Severity Information -LogPath $LogPath
    }
}
