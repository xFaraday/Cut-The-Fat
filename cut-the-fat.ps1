function Invoke-Fatburn {
<#
.SYNOPSIS

This script aims to cut the fat of windows while maintaining functionality.  The goal of cutting back on unnecessary 
bloatware is to reduce CPU usage at start up and idle CPU usage.

.PARAMETER All

Run every script

.PARAMETER Win10

Specifies to be run on windows 10

.PARAMETER Serv

Specifies to be run on Windows Server

#>
[CmdletBinding(DefaultParameterSetName="default")]
Param(
    [Parameter()]
    [switch]$All,
    [Parameter()]
    [switch]$Win10,
    [Parameter()]
    [switch]$Serv
)

function startup {
    #$startupnames = (gcim win32_startupcommand).Name 
    $startups = gcim win32_startupcommand
    #White list of good startup names
    [regex]$WhiteList = 'SecurityHealth | (Default) | VMWare User Process'
    foreach ($startup in $startups) {
    $reg=($startup).Location
    $reg = $reg.Insert(0,'registry::')
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
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

function visualreg {
    #live tiles
    reg ADD "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoTileApplicationsNotification /t REG_DWORD /d 1 /f
    #People in taskbar
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
    #suggestions start menu
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
    
    #Keys that add the desktop and how it handles tasks related to it 
    reg ADD "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 75 /f
    reg ADD "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
    
    #APPLYING VISUAL SETTINGS FOR BEST PERFORMANCE...finally found the key
    reg ADD "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
}

function trackwack {
    #disable cortana
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

    #Disable telemetry
    #Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" Allow Telemetry -Value 0
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "Allow Telemetry" /t REG_DWORD /d 0 /f
    #Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\DataCollection" Allow Telemetry -Value 0
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "Allow Telemetry" /t REG_DWORD /d 0 /f 

    #telemetry tasks
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
    schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

    #do not track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #disable advertising info
    reg ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

    #prevent bloatware from coming back from the dead
    #Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" DisableWindowsConsumerFeatures -Value 1
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
}

function update {
    #set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" AUOptions -Value 1
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "Auto Update" /t REG_DWORD /d 1 /f
    #set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate -Value 1
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
    #set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AUOptions -Value 2 #Hex Dword value of 2
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f

    #DetectionFrequency enable
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequencyEnabled /t REG_DWORD /d 1 /f
    #DetectionFrequency interval
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequency /t REG_DWORD /d 0x00000016 /f

    #section for background intelligence transfer service

    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling" /v EnableBandwidthLimits /t REG_DWORD /d 1 /f 

    #strict OwO
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling" /v IgnoreBandwidthLimitsOnLan /t REG_DWORD /d 0 /f

    #Work days 
    #goal is to make big work day period so that BITS is limited as much as possible as a limitation is put on work hours
    #from sunday
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v StartDay /t REG_DWORD /d 0 /f
    #to Saturday
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v EndDay /t REG_DWORD /d 6 /f

    #from 12 am 
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v StartHour /t REG_DWORD /d 0 /f
    #to 10 pm
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v EndHour /t REG_DWORD /d 22 /f

    #LIMITATION HAMMER LADIES AND GENTLEMEN
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v HighBandwidthLimit /t REG_DWORD /d 0xFFFFFFA0 /f
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v NormalBandwidthLimit /t REG_DWORD /d 0xFFFFFFA0 /f
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v LowBandwidthLimit /t REG_DWORD /d 0xFFFFFFA0 /f

    #Unit of measure, Mbps
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v HighBandwidthType /t REG_DWORD /d 2 /f
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v NormalBandwidthType /t REG_DWORD /d 2 /f
    reg ADD "HKLM\Software\Policies\Microsoft\Windows\BITS\Throttling\WorkSchedule" /v LowBandwidthType /t REG_DWORD /d 2 /f
}

function windef {
    #max CPU usage
    Set-MpPreference -ScanAvgCPULoadFactor 15
    #low pririoty process
    set-MpPreference -EnableLowCpuPriority $True 
    #real time monitoring
    Set-MpPreference -DisableRealTimeMonitoring $True
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
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
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

#simon lee one drive script
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

#credit to Alex for this part
function keyterm {
    $Keys = @(
        
    #Remove Background Tasks
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
    #Windows File
    "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        
    #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
    #Scheduled Tasks to delete
    "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        
    #Windows Protocol Keys
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
           
    #Windows Share Target
    "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
}

if ($All -and $Win10) {
    startup
    serv
    visualreg
    trackwack
    update
    windef
    apps
    tasks
    onedrive
    keyterm
    reboot
} elseif ($All -and $Serv) {
    startup
    serv
    visualreg
    trackwack
    update
    windef
    apps
    tasks
    onedrive
    keyterm
    reboot
} else {
    Write-Warning "Check Parameters"
}

}

#Invoke-FatBurn -All -Win10
#Invoke-FatBurn -All -Serv
