# Ensure Microsoft Graph is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Predefined OMA-URIs for IG Levels
$IGLevels = @{
    "IG1" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/UserRights/ImpersonateClient"; "value" = "AdministratorsLOCAL SERVICENETWORK SERVICESERVICE"; "dataType" = "String"; "desc" = "Sets impersonation rights" }
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Experience/DisableWindowsConsumerFeatures"; "value" = "1"; "dataType" = "Integer"; "desc" = "Disables consumer features" }
    )
    "IG2" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/UserRights/ChangeSystemTime"; "value" = "AdministratorsLOCAL SERVICE"; "dataType" = "String"; "desc" = "Sets change system time" }
    )
    "IG3" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowActionCenterNotifications"; "value" = "0"; "dataType" = "Integer"; "desc" = "Disables action center notifications" }
    )
    "Level1" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/DisableLockScreen"; "value" = "true"; "dataType" = "Boolean"; "desc" = "Disables lock screen" }
    )
    "Level2" = @(
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
    $profileName = "CIS Benchmark - $level"
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
    $omaSettings = $IGLevels[$level]
    if ($null -eq $omaSettings) {
        Write-Host "❌ No settings found for $level." -ForegroundColor Red
        return
    }
    
    $formattedOmaSettings = @()
    $existingOmaSettings = @()
    if ($keepExisting -and $profileId) {
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }
    
    foreach ($setting in $omaSettings) {
        $omaUri = $setting.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        if (-not $existingEntry) {
            # Adjust value type based on dataType
            $value = $setting.value
            if ($setting.dataType -eq "Integer") {
                $value = [int]$value
                $omaType = "#microsoft.graph.omaSettingInteger"
            } elseif ($setting.dataType -eq "Boolean") {
                $value = [bool]$value
                $omaType = "#microsoft.graph.omaSettingBoolean"
            } else {
                $omaType = "#microsoft.graph.omaSettingString"
            }

            # Add setting to formatted list
            $formattedOmaSettings += @{
                "@odata.type" = $omaType
                "displayName" = $setting.desc
                "omaUri" = $omaUri
                "value" = $value
            }
        }
    }
    
    $profileBody = @{
        "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
        "displayName" = $profileName
        "omaSettings" = $formattedOmaSettings
    }
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

# Function to Add a CSV Configuration
function Add-CSV {
    Write-Host "📂 Select CSV file for upload..." -ForegroundColor Cyan
    $csvFilePath = Read-Host "Enter full path to CSV file"
    if (-Not (Test-Path $csvFilePath)) {
        Write-Host "❌ Error: CSV file not found at $csvFilePath" -ForegroundColor Red
        return
    }
    Write-Host "📋 Enter the policy name to update or create:" -ForegroundColor Cyan
    $policyName = Read-Host "Policy Name"
    $profileId = Get-IntuneProfileId -profileName $policyName
    
    if (-not $profileId) {
        Write-Host "🆕 No existing profile found. Creating a new one..." -ForegroundColor Green
    } else {
        Write-Host "✅ Existing profile found. Updating it..." -ForegroundColor Yellow
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
    
    $csvData = Import-Csv -Path $csvFilePath
    if ($csvData.Count -eq 0) {
        Write-Host "❌ Error: CSV file is empty!" -ForegroundColor Red
        return
    }
    
    $formattedOmaSettings = @()
    $existingOmaSettings = @()
    if ($profileId -and $keepExisting) {
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }
    
    foreach ($row in $csvData) {
        $omaUri = $row.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        
        # Handle value type based on CSV data
        $value = $row.value
        $omaType = "#microsoft.graph.omaSettingString"  # Default type

        if ($value -match '^\d+$') {  # If the value is an integer
            $value = [int]$value
            $omaType = "#microsoft.graph.omaSettingInteger"
        } elseif ($value -match '^(true|false)$') {  # If the value is a boolean
            $value = [bool]$value
            $omaType = "#microsoft.graph.omaSettingBoolean"
        }

        # Use the displayName from the CSV as the setting's displayName
        $displayName = $row.displayName
        $description = $row.description
        
        if (-not $existingEntry) {
            $formattedOmaSettings += @{
                "@odata.type" = $omaType
                "displayName" = $displayName  # Use the displayName from the CSV
                "omaUri" = $omaUri
                "value" = $value
                "description" = $description  # Explicitly set the description field
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
            "2" { Apply-OMASettings -level "IG1" }
            "3" { Apply-OMASettings -level "IG2" }
            "4" { Apply-OMASettings -level "IG3" }
            "5" { Apply-OMASettings -level "Level1" }
            "6" { Apply-OMASettings -level "Level2" }
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