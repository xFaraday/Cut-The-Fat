function Invoke-Fatburn {
<#
.SYNOPSIS

This script aims to cut the fat of windows while maintaining functionality.  The goal of cutting back on unnecessary 
bloatware is to reduce CPU usage at start up and idle CPU usage.

.PARAMETER All

Run every script

#>

[CmdletBinding(DefaultParameterSetName="default")]
Param(
    [Parameter(ParameterSetName='All')]
    [switch]$All

)

function startup {
    #$startupnames = (gcim win32_startupcommand).Name 
    $startups = gcim win32_startupcommand
    #White list of good startup names
    [regex]$WhiteList = 'SecurityHealth | (Default) | VMWare User Process'
    foreach ($startup in $startups) {
    Get-ItemProperty -Path ($startup).Location -Name ($startup).Name | Where-Object {$_.Name -NotMatch $WhiteList} | Set-ItemProperty -Value ([byte[]](0xEF,0xBE,0xAD,0xDE))
    }

}


function serv {
    $services = @(
        "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
        "DiagTrack"                                # Diagnostics Tracking Service
        "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
        "lfsvc"                                    # Geolocation Service
        "MapsBroker"                               # Downloaded Maps Manager
        "RemoteAccess"                             # Routing and Remote Access
        "RemoteRegistry"                           # Remote Registry
        "SharedAccess"                             # Internet Connection Sharing (ICS)
        "TrkWks"                                   # Distributed Link Tracking Client
        "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
        "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
        "XblAuthManager"                           # Xbox Live Auth Manager
        "XblGameSave"                              # Xbox Live Game Save Service
        "XblGipSvc"
        "XboxNetApiSvc"                            # Xbox Live Networking Service
        "ndu"                                      # Windows Network Data Usage Monitor
        "xbgm"                                     # Xbox game stuff

    )
    
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue 
        Set-Service -Name $service -StartupType Disabled -Force -ErrorAction Silently Continue
    }

}

function visualreg {
  #Doesnt look like there is an easy way to set this automatically...will come back to this later

}

function cortanatrack {
    #disable cortana
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" AllowCortana -Value 0

    #Disable telemetry
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" Allow Telemetry -Value 0
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\DataCollection" Allow Telemetry -Value 0
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
    schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

    #do not track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #disable advertising info
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

    #prevent bloatware from coming back from the dead
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" DisableWindowsConsumerFeatures -Value 1

}

function update {
    #might have to use reg add instead
    set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" AUOptions -Value 1
    set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" WindowsUpdate
    set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" AU
    set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate -Value 1
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f
    set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AUOptions -Value 2 #Hex Dword value of 2
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f

}

function windef {
    #max CPU usage
    Set-MpPreference -ScanAvgCPULoadFactor 15
    #low pririoty process
    set-MpPreference -EnableLowCpuPriority $True 
}

function apps {
    $Apps = @(
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"


        "*Microsoft.BingNews*"
        "*Microsoft.BingWeather*"
        "*Microsoft.BingSports*"
        "*Microsoft.BingFinance*"
        "*Microsoft.GetHelp*"
        "*Microsoft.Getstarted*"
        "*Microsoft.Messaging*"
        "*Microsoft.Microsoft3DViewer*"
        "*Microsoft.MicrosoftOfficeHub*"
        "*Microsoft.MicrosoftSolitaireCollection*"
        "*Microsoft.NetworkSpeedTest*"
        "*Microsoft.Office.Sway*"
        "*Microsoft.OneConnect*"
        "*Microsoft.People*"
        "*Microsoft.Print3D*"
        "*Microsoft.SkypeApp*"
        "*Microsoft.WindowsAlarms*"
        "*Microsoft.WindowsCamera*"
        "*microsoft.windowscommunicationsapps*"
        "*Microsoft.WindowsFeedbackHub*"
        "*Microsoft.WindowsMaps*"
        "*Microsoft.WindowsSoundRecorder*"
        "*Microsoft.Xbox.TCUI*"
        "*Microsoft.XboxApp*"
        "*Microsoft.XboxGameOverlay*"
        "*Microsoft.XboxIdentityProvider*"
        "*Microsoft.XboxSpeechToTextOverlay*"
        "*Microsoft.ZuneMusic*"
        "*Microsoft.ZuneVideo*"
        "*Microsoft.YourPhone*"
    )
    foreach ($App in $Apps) {
    Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPriovisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }

}

function tasks {
    $tasks = @(
        "XblGameSaveTaskLogon"
        "XblGameSaveTask"               #xbox garbage
        "Consolidator"                  #customer improvement program
        "UsbCeip"                       #windows improvement program
        "DmClient"                      #Microsoftfeedback
        "DmClientOnScenarioDownload"    #Microsoftfeedback
        "Appraiser"                     #Telemetry
        "ProgramDataUpdater"            #Telemetry
    )
    foreach ($task in $tasks) {
    Get-ScheduledTask | Where-Object {$_.TaskName -eq $task} | Disable-ScheduledTask
    }
}

function onedrive {
#killing onedrive
taskkill /f /im OneDrive.exe
& "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall

#ownership of onedrivesetup.exe
$ACL = Get-ACL -Path $env:SystemRoot\SysWOW64\OneDriveSetup.exe
$Group = New-Object System.Security.Principal.NTAccount("$env:UserName")
$ACL.SetOwner($Group)
Set-Acl -Path $env:SystemRoot\SysWOW64\OneDriveSetup.exe -AclObject $ACL

#Assign full R/W Permissions to $env:UserName (Administrator)
$Acl = Get-Acl "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
$Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$env:UserName","FullControl","Allow")
$Acl.SetAccessRule($Ar)
Set-Acl "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" $Acl
    
REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f

#Remove one drive shortcuts
Remove-Item -Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue

Remove-Item -Path "$env:SystemRoot\SysWOW64\OneDrive.ico" -Force -ErrorAction SilentlyContinue

Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item -Path "C:\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue

}

if ($All) {
    startup
    serv
    visualreg
    cortanatrack
    update
    windef
    apps
    tasks
    onedrive
} else {
    Write-Warning "No Parameter"
}

}

Invoke-FatBurn -All