# Ensure Microsoft Graph is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Predefined OMA-URIs for IG Levels
$IGLevels = @{
    "IG 1" = @(
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen slide show" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Apply UAC restrictions to local accounts on network logons" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel"; 
            "value" = '<enabled/><data id="DisableIPSourceRoutingIPv6" value="2"/>'; 
            "dataType" = "String"; 
            "desc" = "IPv6 source routing protection level"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel"; 
            "value" = '<enabled/><data id="DisableIPSourceRouting" value="2"/>'; 
            "dataType" = "String"; 
            "desc" = "IP source routing protection level"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow ICMP redirects to override OSPF generated routes"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow the computer to ignore NetBIOS name release requests except from WINS servers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod"; 
            "value" = '<enabled/><data id="ScreenSaverGracePeriod" value="5"/>'; 
            "dataType" = "String"; 
            "desc" = "The time in seconds before the screen saver grace period expires 5 or fewer seconds"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_WarningLevel"; 
            "value" = '<enabled/><data id="WarningLevel" value="90"/>'; 
            "dataType" = "String"; 
            "desc" = "Percentage threshold for the security event log at which the system will generate a warning"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit installation and configuration of Network Bridge on your DNS domain network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit use of Internet Connection Sharing on your DNS domain network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Require domain users to elevate when setting a network's location"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths"; 
            "value" = '<enabled/><data id="Pol_HardenedPaths" value="\\NETLOGONRequireMutualAuthentication=1,RequireIntegrity=1\\SYSVOLRequireMutualAuthentication=1,RequireIntegrity=1"/>'; 
            "dataType" = "String"; 
            "desc" = "Hardened UNC Paths"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_WCM/WCM_MinimizeConnections"; 
            "value" = '<enabled/><data id="WCM_MinimizeConnections_Options" value="3"/>'; 
            "dataType" = "String"; 
            "desc" = "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsConnectionManager/ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit connection to non-domain networks when connected to domain authenticated network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WirelessDisplay/RequirePinForPairing"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Require PIN pairing"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Printing2/RegisterSpoolerRemoteRpcEndPoint"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow Print Spooler to accept client connections"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions"; 
            "value" = '<data id="PointAndPrint_TrustedServers_Chk" value="false"/><data id="PointAndPrint_TrustedServers_Edit" value=""/><data id="PointAndPrint_TrustedForest_Chk" value="false"/><data id="PointAndPrint_NoWarningNoElevationOnInstall_Enum" value="0"/><data id="PointAndPrint_NoWarningNoElevationOnUpdate_Enum" value="0"/'; 
            "dataType" = "String"; 
            "desc" = "Point and Print Restrictions: When updating or installg drivers for an existing connection"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off toast notifications on the lock screen (User)"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_CredSsp/AllowEncryptionOracle"; 
            "value" = '<enabled/><data id="AllowEncryptionOracleDrop" value="0"/>'; 
            "dataType" = "String"; 
            "desc" = "Encryption Oracle Remediation"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/CSE_Registry"; 
            "value" = '<enabled/><data id="CSE_NOBACKGROUND10" value="false"/>'; 
            "dataType" = "String"; 
            "desc" = "Configure security policy processing"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/DisableBackgroundPolicy"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off background refresh of Group Policy"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/BlockUserFromShowingAccountDetailsOnSignin"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Block user from showing account details on sign-in"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not display network selection UI"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/DontEnumerateConnectedUsers"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not enumerate connected users on domain-joined computers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnumerateLocalUsersOnDomainJoinedComputers"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Enumerate local users on domain-joined computers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Disallow Autoplay for non-volume devices"
         }
        @{ 
            "omaUri" = "./User/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Disallow Autoplay for non-volume devices"
         }
    )
    "IG 2" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/UserRights/ChangeSystemTime"; "value" = "AdministratorsLOCAL SERVICE"; "dataType" = "String"; "desc" = "Sets change system time" }
    )
    "IG 3" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowActionCenterNotifications"; "value" = "0"; "dataType" = "Integer"; "desc" = "Disables action center notifications" }
    )
    "Level 1" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/DisableLockScreen"; "value" = "true"; "dataType" = "Boolean"; "desc" = "Disables lock screen" }
    )
    "Level 2" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Experience/DisableWindowsConsumerFeatures"; "value" = "1"; "dataType" = "Integer"; "desc" = "Disables consumer features" }
    )
}

# Function to authenticate with Microsoft Graph
function Connect-ToIntune {
    Write-Host "🔄 Logging into Microsoft Intune..." -ForegroundColor Cyan
    try {
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"
        Write-Host "✅ Successfully authenticated with Intune." -ForegroundColor Green
    } catch {
        Write-Host "❌ Error: Failed to authenticate with Intune." -ForegroundColor Red
    }
}

# Function to get existing Intune policy ID
function Get-IntuneProfileId {
    param ([string]$profileName)
    $profiles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
    
    foreach ($profile in $profiles.value) {
        if ($profile.displayName -eq $profileName) {
            return $profile.id
        }
    }
    return $null
}

# Function to apply policy settings
function Apply-OMASettings {
    param ([string]$level)
    
    $omaSettings = $IGLevels[$level]
    if ($null -eq $omaSettings) {
        Write-Host "❌ No settings found for $level." -ForegroundColor Red
        return
    }
    
    $deviceSettings = @()
    $userSettings = @()
    
    foreach ($setting in $omaSettings) {
        if ($setting.omaUri -match "\.\/Device\/.*") {
            $deviceSettings += $setting
        } elseif ($setting.omaUri -match "\.\/User\/.*") {
            $userSettings += $setting
        } else {
            $deviceSettings += $setting  # Default to Device if it's not explicitly for Users
        }
    }
    
    $policiesCreated = 0
    
    if ($deviceSettings.Count -gt 0) {
        Apply-IntunePolicy -level $level -settings $deviceSettings -profileType "Device"
        $policiesCreated++
    }
    
    if ($userSettings.Count -gt 0) {
        Apply-IntunePolicy -level $level -settings $userSettings -profileType "Users"
        $policiesCreated++
    }
    
    if ($policiesCreated -eq 2) {
        Write-Host "⚠️ Both Device and User policies created for $level." -ForegroundColor Yellow
    }
}

# Function to create/update Intune policies
function Apply-IntunePolicy {
    param ([string]$level, [array]$settings, [string]$profileType)
    
    $profileName = "CIS Benchmark - $level ($profileType)"
    Write-Host "📋 Checking if profile '$profileName' exists..." -ForegroundColor Cyan
    $profileId = Get-IntuneProfileId -profileName $profileName
    
    $keepExisting = $true
    if ($profileId) {
        do {
            $response = Read-Host "Do you want to keep existing settings? (Yes/No)"
            if ($response -eq "No") {
                $keepExisting = $false
            } elseif ($response -eq "Yes") {
                $keepExisting = $true
            } else {
                Write-Host "❌ Invalid input. Please enter 'Yes' or 'No'." -ForegroundColor Red
            }
        } until ($response -eq "Yes" -or $response -eq "No")
    }
    
    $formattedOmaSettings = @()
    $existingOmaSettings = @()
    
    if ($keepExisting -and $profileId) {
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }
    
    foreach ($setting in $settings) {
        $omaUri = $setting.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        if (-not $existingEntry) {
            $value = $setting.value
            $omaType = switch ($setting.dataType) {
                "Integer" { "#microsoft.graph.omaSettingInteger"; $value = [int]$value }
                "Boolean" { "#microsoft.graph.omaSettingBoolean"; $value = [bool]$value }
                Default { "#microsoft.graph.omaSettingString" }
            }
            
            $formattedOmaSettings += @{ "@odata.type" = $omaType; "displayName" = $setting.desc; "omaUri" = $omaUri; "value" = $value }
        }
    }
    
    $profileBody = @{ "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"; "displayName" = $profileName; "omaSettings" = $formattedOmaSettings }
    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress
    
    try {
        if ($profileId) {
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ Profile updated successfully: $profileName" -ForegroundColor Green
        } else {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ New profile created successfully: $profileName" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Error updating or creating profile: $_" -ForegroundColor Red
    }
}

Add-Type -AssemblyName System.Windows.Forms

# Function to launch file explorer and select a file
function Get-FilePath {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.InitialDirectory = [System.Environment]::GetFolderPath('MyDocuments')
    $dialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dialog.RestoreDirectory = $true
    
    if ($dialog.ShowDialog() -eq 'OK') {
        return $dialog.FileName
    } else {
        Write-Host "No file selected."
        return $null
    }
}

# Function to Add a CSV Configuration
function Add-CSV {
    Write-Host "📂 Select CSV file for upload..." -ForegroundColor Cyan
    $csvFilePath = Get-FilePath
    if (-Not $csvFilePath) {
        Write-Host "❌ Error: CSV file not found or user canceled." -ForegroundColor Red
        return
    }
    
    Write-Host "🗉 Enter the base policy name to update or create:" -ForegroundColor Cyan
    $basePolicyName = Read-Host "Policy Name"
    
    $csvData = Import-Csv -Path $csvFilePath
    if ($csvData.Count -eq 0) {
        Write-Host "❌ Error: CSV file is empty!" -ForegroundColor Red
        return
    }
    
    # Trim spaces in omaUri field to avoid filtering issues
    $csvData | ForEach-Object { $_.omaUri = $_.omaUri.Trim() }
    
    # Debugging: Print all OMA-URI entries before filtering
    Write-Host "📜 Full list of OMA-URIs found in CSV (after trimming):" -ForegroundColor Cyan
    foreach ($entry in $csvData) {
        Write-Host "   - [$($entry.omaUri)]" -ForegroundColor Yellow
    }
    
    # Adjust filtering using -like for better wildcard matching
    $deviceSettings = @($csvData | Where-Object { $_.omaUri -like "*/Device/*" })
    $userSettings = @($csvData | Where-Object { $_.omaUri -like "*/User/*" })
    
    Write-Host "✅ Identified $($deviceSettings.Count) Device settings and $($userSettings.Count) User settings." -ForegroundColor Green
    
    if ($deviceSettings.Count -gt 0) {
        Write-Host "➡️ Processing Device Policy: $basePolicyName (Device)" -ForegroundColor Cyan
        Process-Policy "$basePolicyName (Device)" $deviceSettings
    }
    
    if ($userSettings.Count -gt 0) {
        Write-Host "➡️ Processing User Policy: $basePolicyName (User) with $($userSettings.Count) settings." -ForegroundColor Cyan
        foreach ($entry in $userSettings) {
            Write-Host "   📌 Found User Setting: [$($entry.omaUri)]" -ForegroundColor Cyan
        }
        Process-Policy "$basePolicyName (User)" $userSettings
    } else {
        Write-Host "⚠️ No User settings found! Skipping User policy creation." -ForegroundColor Yellow
        Write-Host "🔎 Debug: Double-checking all OMA-URIs in CSV to verify filtering." -ForegroundColor Magenta
        foreach ($entry in $csvData) {
            Write-Host "   🛑 Unmatched Entry: [$($entry.omaUri)]" -ForegroundColor Red
        }
    }
}

function Process-Policy {
    param (
        [string]$policyName,
        [array]$settingsData
    )

    if ($settingsData.Count -eq 0) {
        Write-Host "⚠️ No settings provided for policy: $policyName. Skipping..." -ForegroundColor Yellow
        return
    }
    
    Write-Host "🔄 Processing policy: $policyName with $($settingsData.Count) settings..." -ForegroundColor Cyan
    $profileId = Get-IntuneProfileId -profileName $policyName
    
    if (-not $profileId) {
        Write-Host "🆕 No existing profile found. Creating a new one..." -ForegroundColor Green
    } else {
        Write-Host "✅ Existing profile found: $policyName. Updating it..." -ForegroundColor Yellow
        do {
            $response = Read-Host "Do you want to keep existing settings? (Yes/No)"
            if ($response -eq "No") {
                $keepExisting = $false
            } elseif ($response -eq "Yes") {
                $keepExisting = $true
            } else {
                Write-Host "❌ Invalid input. Please enter 'Yes' or 'No'." -ForegroundColor Red
            }
        } until ($response -eq "Yes" -or $response -eq "No")
    }
    
    $formattedOmaSettings = @()
    $existingOmaSettings = @()
    if ($profileId -and $keepExisting) {
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }
    
    foreach ($row in $settingsData) {
        $omaUri = $row.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        
        $value = $row.value
        $omaType = "#microsoft.graph.omaSettingString"
        
        if ($value -match '^\d+$') {
            $value = [int]$value
            $omaType = "#microsoft.graph.omaSettingInteger"
        } elseif ($value -match '^(true|false)$') {
            $value = [bool]$value
            $omaType = "#microsoft.graph.omaSettingBoolean"
        }

        $displayName = $row.displayName
        $description = $row.description
        
        if (-not $existingEntry) {
            $formattedOmaSettings += @{
                "@odata.type" = $omaType
                "displayName" = $displayName
                "omaUri" = $omaUri
                "value" = $value
                "description" = $description
            }
        }
    }
    
    $profileBody = @{
        "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
        "displayName" = $policyName
        "omaSettings" = $formattedOmaSettings
    }
    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress
    try {
        if ($profileId) {
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ Policy updated successfully: $policyName" -ForegroundColor Green
        } else {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ New policy created successfully: $policyName" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Error updating or creating policy: $_" -ForegroundColor Red
    }
}




# Submenu for Intune Windows 10/11 Configuration Policies
function Show-IntuneMenu {
    while ($true) {
        Write-Host "🔧 Intune Windows 10/11 Configuration Policies" -ForegroundColor Cyan
        Write-Host "1. Login to Microsoft Intune"
        Write-Host "2. Apply IG 1 Policy"
        Write-Host "3. Apply IG 2 Policy"
        Write-Host "4. Apply IG 3 Policy"
        Write-Host "5. Apply Level 1 Policy"
        Write-Host "6. Apply Level 2 Policy"
        Write-Host "7. Upload from File"
        Write-Host "8. Back to Main Menu"
        
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" { Connect-ToIntune }
            "2" { Apply-OMASettings -level "IG 1" }
            "3" { Apply-OMASettings -level "IG 2" }
            "4" { Apply-OMASettings -level "IG 3" }
            "5" { Apply-OMASettings -level "Level 1" }
            "6" { Apply-OMASettings -level "Level 2" }
            "7" { Add-CSV }
            "8" { return }
            default { Write-Host "❌ Invalid option." -ForegroundColor Red }
        }
    }
}

# Main menu
function Show-MainMenu {
    while ($true) {
        Write-Host "📌 Main Menu" -ForegroundColor Cyan
        Write-Host "1. Intune Windows 10/11 Configuration Policies"
        Write-Host "2. Placeholder for Future Features"
        Write-Host "3. Exit Script (Return to PowerShell Prompt)"
        
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" { Show-IntuneMenu }
            "2" { Write-Host "🚧 Feature under development. Returning to main menu..." -ForegroundColor Yellow }
            "3" { Write-Host "✅ Returning to PowerShell..."; return }
            default { Write-Host "❌ Invalid option. Please enter a number between 1 and 3." -ForegroundColor Red }
        }
    }
}

# Start the Main Menu
Show-MainMenu