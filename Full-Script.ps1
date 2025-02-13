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

# Function to apply predefined OMA-URI settings under one profile
function Apply-OMASettings {
    param ([string]$level)

    # Define profile name with prefix
    $profileName = "CIS Benchmark - $level"

    Write-Host "📋 Checking if profile '$profileName' exists..." -ForegroundColor Cyan
    $profileId = Get-IntuneProfileId -profileName $profileName

    # Fetch existing settings if profile exists
    if ($profileId) {
        Write-Host "✅ Profile '$profileName' found. Updating..." -ForegroundColor Yellow
        $existingOmaSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
    } else {
        Write-Host "🆕 Profile '$profileName' not found. Creating a new policy..." -ForegroundColor Green
        $existingOmaSettings = @()
    }

    # Get OMA-URI settings for selected level
    $omaSettings = $IGLevels[$level]

    if ($null -eq $omaSettings) {
        Write-Host "❌ No settings found for IG Level $level." -ForegroundColor Red
        return
    }

    # Prepare JSON body with correct data types
    $formattedOmaSettings = @()
    foreach ($setting in $omaSettings) {
        $omaUri = $setting.omaUri
        $displayName = "CIS - " + ($setting.omaUri -split "/")[-1] # Shorten name
        $description = $setting.desc.Substring(0, [Math]::Min(64, $setting.desc.Length)) # Limit to 64 chars
        $valueData = $setting.value
        $omaSettingType = "#microsoft.graph.omaSettingString"

        if ($setting.dataType -eq "Integer") { $omaSettingType = "#microsoft.graph.omaSettingInteger"; $valueData = [int]$valueData }
        if ($setting.dataType -eq "Boolean") { $omaSettingType = "#microsoft.graph.omaSettingBoolean"; $valueData = [bool]::Parse($valueData) }

        $formattedOmaSettings += @{
            "@odata.type" = $omaSettingType
            "displayName" = $displayName
            "description" = $description
            "omaUri" = $omaUri
            "value" = $valueData
        }
    }

    # Construct JSON payload with explicit configuration type
    $profileBody = @{
        "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"  # FIX: Explicit policy type
        "displayName" = $profileName
        "description" = "CIS Benchmark for $level"
        "omaSettings" = $formattedOmaSettings
    }

    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress

    # Update existing profile or create a new one
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

    # Read and Validate CSV
    $csvData = Import-Csv -Path $csvFilePath
    if ($csvData.Count -eq 0) {
        Write-Host "❌ Error: CSV file is empty!" -ForegroundColor Red
        return
    }

    # Check if policy exists
    $profileId = Get-IntuneProfileId -profileName $policyName
    if ($profileId) {
        Write-Host "🔄 Policy '$policyName' found. Updating..." -ForegroundColor Yellow
    } else {
        Write-Host "🆕 Policy '$policyName' not found. Creating a new one..." -ForegroundColor Green
    }

    # Convert CSV to JSON Format
    $formattedOmaSettings = @()
    foreach ($row in $csvData) {
        $displayName = $row.displayName
        $omaUri = $row.omaUri
        $value = $row.value
        $description = $row.description.Substring(0, [Math]::Min(64, $row.description.Length)) # Limit to 64 chars
        $dataType = $row.dataType

        # Determine correct OMA Setting Type
        $omaSettingType = "#microsoft.graph.omaSettingString"
        if ($dataType -eq "Integer") { $omaSettingType = "#microsoft.graph.omaSettingInteger"; $value = [int]$value }
        if ($dataType -eq "Boolean") { $omaSettingType = "#microsoft.graph.omaSettingBoolean"; $value = [bool]::Parse($value) }

        # Construct OMA-URI object
        $formattedOmaSettings += @{
            "@odata.type" = $omaSettingType
            "displayName" = $displayName
            "description" = $description
            "omaUri" = $omaUri
            "value" = $value
        }
    }

    # Construct JSON payload
    $profileBody = @{
        "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
        "displayName" = $policyName
        "description" = "CIS Benchmark Policy"
        "omaSettings" = $formattedOmaSettings
    }

    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress
    
    Write-Host "🔍 Debug JSON Output:" -ForegroundColor Blue
    Write-Host $jsonBody

    # Send request to Intune
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
            default { Write-Host "❌ Invalid option. Please enter a number between 1 and 8." -ForegroundColor Red }
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

