# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

# Script Purpose:
# This script automates the management of primary users for Windows devices in Intune
# by analyzing sign-in patterns and updating device assignments accordingly.
#
# It does not handle license assignment or provisioning.

# Main Functions:
# 1. Authenticates to Microsoft Entra
# 2. Fetches Intune Windows devices
# 3. Analyzes last 30 days of sign-in logs
# 4. Identifies frequent users per device
# 5. Updates primary user assignments

# ===== CONFIGURATION =====
# Define key variables and settings
$ProgressPreference = 'SilentlyContinue'  # Suppress verbose download progress
$debug = $false

# REQUIRED: Set these environment variables or replace with your values
$clientId = $env:INTUNE_CLIENT_ID          # Your Entra app registration Client ID
$clientSecret = $env:INTUNE_CLIENT_SECRET  # Your Entra app registration Client Secret
$tenantId = $env:INTUNE_TENANT_ID         # Your Entra tenant ID (e.g., contoso.onmicrosoft.com or GUID)

# OPTIONAL: Set this to exclude devices from primary user updates
$excludeGroupId = $env:INTUNE_EXCLUDE_GROUP_ID  # Entra group ID containing device display names to exclude

# Track summary
$script:summary = @{
    TotalDevices           = 0
    MismatchedDevices      = 0
    SkippedDisabledUsers   = 0
    SkippedExcludedDevices = 0
    DevicesUpdated         = 0
    DebugOnly              = 0
    UserLookupFailures     = 0
}

# ========== AUTH ==========

try {
    $tokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    $accessToken = $tokenResponse.access_token

    if (-not $accessToken) {
        throw "Failed to obtain access token."
    }

    $script:headers = @{ Authorization = "Bearer $accessToken" }
    Write-Host "Successfully authenticated to Microsoft Graph."
}
catch {
    Write-Error "Failed to authenticate: $_"
    return
}

# ========== HELPER FUNCTION ==========

function Invoke-PrimaryUserUpdate {
    param (
        [string]$DeviceName,
        [string]$DeviceId,
        [string]$CurrentPrimaryUser,
        [string]$NewUserId,
        [string]$NewUserUPN
    )

    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/users/`$ref"
    $body = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$NewUserId" } | ConvertTo-Json

    # Retry to handle Intune backend license-cache lag (Azure AD shows license active,
    # but Intune service cache can take several minutes to sync).
    $maxRetries = 5
    $retryDelay = 60
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $accessToken" } -Method Post -Body $body -ContentType "application/json"
            Write-Host "Updated device: $DeviceName | Old Primary User: $CurrentPrimaryUser | New Primary User: $NewUserUPN"
            $script:summary.DevicesUpdated++
            return
        }
        catch {
            $errMsg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"

            if ($errMsg -like "*does not have intune license*") {
                if ($i -lt $maxRetries) {
                    Write-Host "Intune backend not yet synced for '$NewUserUPN' on '$DeviceName'. Retry $i of $($maxRetries - 1) in $retryDelay seconds..."
                    Start-Sleep -Seconds $retryDelay
                    continue
                }
                Write-Warning "Skipping device '$DeviceName' — Intune backend still reports user '$NewUserUPN' as unlicensed after $maxRetries attempts."
                return
            }

            Write-Error "Failed to update primary user for device: $DeviceName. Error: $_"
            return
        }
    }
}


# ========== STEP 1: FETCH INTUNE DEVICES ==========

Write-Host "Fetching Intune device data..."
$deviceUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,azureADDeviceId,userPrincipalName"
$rawDevices = @()
do {
    $response = Invoke-RestMethod -Uri $deviceUri -Headers @{ Authorization = "Bearer $accessToken" } -Method Get -StatusCodeVariable "statusCode" -SkipHttpErrorCheck
    if ($statusCode -eq 429) {
        $retryAfter = 30
        Write-Host "Throttled. Waiting $retryAfter seconds..."
        Start-Sleep -Seconds $retryAfter
    }
    elseif ($statusCode -ge 400) {
        Write-Error "API Error ($statusCode): $($response | ConvertTo-Json -Compress)"
        throw "Failed to fetch devices: HTTP $statusCode"
    }
    else {
        $rawDevices += $response.value
        $deviceUri = $response.'@odata.nextLink'
    }
} while ($deviceUri)

$intuneDevices = $rawDevices | ForEach-Object {
    [PSCustomObject]@{
        DeviceName      = $_.deviceName
        IntuneDeviceId  = $_.id
        AzureAdDeviceId = $_.azureADDeviceId
        PrimaryUser     = $_.userPrincipalName
    }
}
$summary.TotalDevices = $intuneDevices.Count

# ========== STEP 2: FETCH ENTRA SIGN-IN LOGS ==========

Write-Host "Fetching sign-in logs..."
$start = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
$filter = "appDisplayName eq 'Windows Sign In' and isInteractive eq true and clientAppUsed eq 'Mobile Apps and Desktop clients' and status/errorCode eq 0 and createdDateTime gt $start and deviceDetail/operatingSystem eq 'Windows'"
$select = "userPrincipalName,createdDateTime,deviceDetail,clientAppUsed"
$baseLogsUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$select=$select"
$logsUri = $baseLogsUri
$logs = @()
$maxRetries = 3
$retryCount = 0
do {
    $response = Invoke-RestMethod -Uri $logsUri -Headers @{ Authorization = "Bearer $accessToken" } -Method Get -StatusCodeVariable "statusCode" -SkipHttpErrorCheck
    if ($statusCode -eq 429) {
        $retryAfter = 30
        Write-Host "Throttled. Waiting $retryAfter seconds..."
        Start-Sleep -Seconds $retryAfter
    }
    elseif ($statusCode -eq 400 -and $response.error.message -match "Skip token") {
        # Skip token expired - restart from beginning with collected data
        $retryCount++
        if ($retryCount -ge $maxRetries) {
            Write-Warning "Skip token expired $maxRetries times. Proceeding with $($logs.Count) logs collected."
            break
        }
        Write-Warning "Skip token expired. Restarting pagination (attempt $retryCount of $maxRetries)..."
        $logsUri = $baseLogsUri
        Start-Sleep -Seconds 2
    }
    elseif ($statusCode -ge 400) {
        Write-Error "API Error ($statusCode): $($response | ConvertTo-Json -Compress)"
        throw "Failed to fetch sign-in logs: HTTP $statusCode"
    }
    else {
        $logs += $response.value
        $logsUri = $response.'@odata.nextLink'
        $retryCount = 0  # Reset retry count on successful request
    }
} while ($logsUri)

# ========== STEP 3: CALCULATE FREQUENT USERS ==========

Write-Host "Calculating Frequent Users..."
$userDeviceUsage = $logs | Where-Object { $_.DeviceDetail.DeviceId } | Group-Object -Property @{
    Expression = { "$($_.DeviceDetail.DeviceId)|$($_.UserPrincipalName)" }
} | ForEach-Object {
    $parts = $_.Name -split '\|'
    [PSCustomObject]@{
        AzureAdDeviceId = $parts[0]
        SignInUser      = $parts[1]
        SignInCount     = $_.Count
    }
}

$frequentUsers = $userDeviceUsage | Group-Object -Property AzureAdDeviceId | ForEach-Object {
    $_.Group | Sort-Object -Property SignInCount -Descending | Select-Object -First 1
}
$freqMap = @{}
foreach ($f in $frequentUsers) { $freqMap[$f.AzureAdDeviceId] = $f }

# ========== STEP 4: Compare & Detect Mismatches ==========

$comparison = foreach ($device in $intuneDevices) {
    $match = $freqMap[$device.AzureAdDeviceId]
    if ($match) {
        [PSCustomObject]@{
            DeviceName      = $device.DeviceName
            IntuneDeviceId  = $device.IntuneDeviceId
            AzureAdDeviceId = $device.AzureAdDeviceId
            PrimaryUser     = $device.PrimaryUser
            FrequentUser    = $match.SignInUser
            SignInCount     = $match.SignInCount
            MatchStatus     = if ($device.PrimaryUser -eq $match.SignInUser) { "Match" } else { "Mismatch" }
        }
    }
}

$mismatches = $comparison | Where-Object { $_.MatchStatus -eq "Mismatch" }
$summary.MismatchedDevices = $mismatches.Count

# ========== STEP 5: Cache Users ==========

$userCache = @{}
$uniqueUsers = $mismatches.FrequentUser | Sort-Object -Unique

foreach ($upn in $uniqueUsers) {
    try {
        $user = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn`?`$select=id,userPrincipalName,accountEnabled" -Headers @{ Authorization = "Bearer $accessToken" } -Method Get
        $userCache[$upn] = $user
    }
    catch {
        Write-Warning "Failed to lookup user '$upn': $_"
        $summary.UserLookupFailures++
    }
}

# ========== STEP 6: Update Primary Users ==========

foreach ($device in $mismatches) {
    try {
        # Check if device is in excluded group (cached outside loop for performance)
        if ($excludeGroupId) {
            if (-not $excludedDeviceNames) {
                $excludeUri = "https://graph.microsoft.com/v1.0/groups/$excludeGroupId/transitiveMembers?`$select=displayName"
                $excludedMembers = @()
                do {
                    $exResponse = Invoke-RestMethod -Uri $excludeUri -Headers @{ Authorization = "Bearer $accessToken" } -Method Get
                    $excludedMembers += $exResponse.value
                    $excludeUri = $exResponse.'@odata.nextLink'
                } while ($excludeUri)
                $script:excludedDeviceNames = $excludedMembers.displayName
            }
            if ($excludedDeviceNames -contains $device.DeviceName) {
                Write-Host "Primary user will not be updated on $($device.DeviceName) as it's in the excluded group"
                $summary.SkippedExcludedDevices++
                continue
            }
        }

        $frequentUserUPN = $device.FrequentUser
        if (-not $userCache.ContainsKey($frequentUserUPN)) { continue }

        $user = $userCache[$frequentUserUPN]

        if (-not $user.accountEnabled) {
            Write-Host "Primary user will not be updated on $($device.DeviceName) as user $frequentUserUPN is disabled"
            $summary.SkippedDisabledUsers++
            continue
        }

        if ($debug) {
            Write-Host "[DEBUG] Would update: $($device.DeviceName) | From: $($device.PrimaryUser) → $frequentUserUPN"
            $summary.DebugOnly++
        }
        else {
            Invoke-PrimaryUserUpdate -DeviceName $device.DeviceName `
                -DeviceId $device.IntuneDeviceId `
                -CurrentPrimaryUser $device.PrimaryUser `
                -NewUserId $user.Id `
                -NewUserUPN $frequentUserUPN
        }

    }
    catch {
        Write-Warning "Error with device '$($device.DeviceName)': $_"
    }
}

# ========== FINAL SUMMARY ==========

Write-Host ""
Write-Host "===== Execution Summary ====="
Write-Host "Total Devices Checked        : $($summary.TotalDevices)"
Write-Host "Mismatched Primary Users     : $($summary.MismatchedDevices)"
Write-Host "Skipped (Disabled Users)     : $($summary.SkippedDisabledUsers)"
Write-Host "User Lookup Failures         : $($summary.UserLookupFailures)"
Write-Host "Devices Updated              : $($summary.DevicesUpdated)"
Write-Host "Debug Simulated Updates      : $($summary.DebugOnly)"
