# BlueBear Windows Installer
# DEN-275: PowerShell installer script with OAuth device flow authentication
# DEN-750: Updated for single binary architecture (unified handler)
#
# Usage:
#   # Interactive install (opens browser for authentication)
#   irm https://install.bluebearsecurity.io/windows | iex
#
#   # Or run directly
#   .\install.ps1
#
#   # With custom API URL (for development)
#   $env:BLUEDEN_API_URL = "https://api-pr-123.dev.bluebearsecurity.io"
#   .\install.ps1

#Requires -Version 5.1

param(
    [string]$ApiUrl = $env:BLUEDEN_API_URL,
    [string]$ConsoleUrl = $env:BLUEDEN_CONSOLE_URL,
    [string]$InstallDir = $null,
    [switch]$NoAddToPath,
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Speeds up Invoke-WebRequest

# Default URLs
if (-not $ApiUrl) { $ApiUrl = "https://api.bluebearsecurity.io" }
if (-not $ConsoleUrl) { $ConsoleUrl = "https://app.bluebearsecurity.io" }

# Installation paths
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "BlueBear"
}
$BinDir = Join-Path $InstallDir "bin"

# Version - will be replaced by CI/CD (e.g., 0.0.478 for PR, 1.2.3 for prod)
$Version = "0.5.1"

# Detect PR version from API URL if not replaced by CI/CD
if ($Version -eq "__VERSION__") {
    if ($ApiUrl -match "api-pr-(\d+)") {
        # For local dev: use PR number as version for S3 path compatibility
        $Version = "0.0.$($Matches[1])"
    } else {
        # Fallback to latest for production when version not set
        $Version = "latest"
    }
}

# DEN-750: Detect environment from API URL for config dir and exe naming
# This is separate from Version because Version is used for S3 download path
$Environment = ""
if ($ApiUrl -match "api-pr-(\d+)") {
    $Environment = "pr-$($Matches[1])"
}

# DEN-750: Config directory matches Go binary's environmentSuffix
# PR environments use .bluebear-pr-{N}, production uses .bluebear
if ($Environment -match "^pr-\d+$") {
    $ConfigDir = Join-Path $env:USERPROFILE ".bluebear-$Environment"
} else {
    $ConfigDir = Join-Path $env:USERPROFILE ".bluebear"
}
$ConfigFile = Join-Path $ConfigDir "config"

# DEN-750: Single binary architecture
# All clients (Claude, Copilot, Cursor, Codex) are now handled by a single unified binary

# Helper functions
function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    switch ($Type) {
        "Success" { Write-Host "==> " -ForegroundColor Green -NoNewline; Write-Host $Message }
        "Warning" { Write-Host "==> " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
        "Error" { Write-Host "==> " -ForegroundColor Red -NoNewline; Write-Host $Message }
        default { Write-Host "==> " -ForegroundColor Cyan -NoNewline; Write-Host $Message }
    }
}

function Write-Detail {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

function Test-ValidUrl {
    # Validate URL is a proper HTTPS URL to prevent SSRF attacks
    param([string]$Url, [string]$Name)

    if (-not $Url) {
        Write-Status "$Name URL is required" -Type "Error"
        return $false
    }

    # Must be HTTPS
    if (-not $Url.StartsWith("https://")) {
        Write-Status "$Name URL must use HTTPS: $Url" -Type "Error"
        return $false
    }

    # Parse URL to validate format
    try {
        $uri = [System.Uri]::new($Url)

        # Must have valid host
        if ([string]::IsNullOrEmpty($uri.Host)) {
            Write-Status "$Name URL has invalid host: $Url" -Type "Error"
            return $false
        }

        # Block localhost/internal IPs for production
        $urlHost = $uri.Host.ToLower()
        if ($urlHost -eq "localhost" -or $urlHost -eq "127.0.0.1" -or $urlHost.StartsWith("192.168.") -or $urlHost.StartsWith("10.") -or $urlHost.StartsWith("172.")) {
            # Allow for development but warn
            Write-Status "$Name URL points to local/internal address: $Url" -Type "Warning"
        }

        return $true
    } catch {
        Write-Status "$Name URL is malformed: $Url" -Type "Error"
        return $false
    }
}

function Set-ConfigFilePermissions {
    # Config file is in user's profile folder (~\.bluebear) which is already protected
    # by Windows user profile permissions. No additional ACL changes needed.
    # The developer_api_key is stored in this config file for simplicity.
    # Windows user profile permissions provide adequate protection.
    param([string]$FilePath)

    # Just mark the file as hidden for extra obscurity (optional, non-critical)
    try {
        $file = Get-Item $FilePath -Force
        $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
    } catch {
        # Ignore errors - this is just cosmetic
    }

    return $true
}

function Write-ConfigFile {
    # Safely write to config file, handling edge cases like:
    # - Config path exists as a directory (cleanup from failed installs)
    # - Config file exists with restrictive permissions
    # - Config file is locked by another process
    param(
        [string]$FilePath,
        [string]$Content
    )

    $parentDir = Split-Path -Parent $FilePath

    # Ensure parent directory exists
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    # Remove existing file/directory at config path
    if (Test-Path $FilePath) {
        try {
            # Reset attributes first (in case it's hidden/readonly)
            $item = Get-Item $FilePath -Force
            $item.Attributes = [System.IO.FileAttributes]::Normal
        } catch {
            # Ignore attribute reset errors
        }
        Remove-Item -Path $FilePath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Write UTF-8 without BOM (PowerShell 5.1 compatible)
    [System.IO.File]::WriteAllText($FilePath, $Content, [System.Text.UTF8Encoding]::new($false))
}

# Note: Credential Manager functions removed in favor of config file storage
# The developer_api_key is now stored in ~/.bluebear/config file
# Windows user profile permissions provide adequate protection

function Test-ExistingConfig {
    # Check for existing configuration (API key and endpoint in config file)
    if (Test-Path $ConfigFile) {
        try {
            $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($config.api_endpoint -and $config.developer_api_key) {
                return $config
            }
        } catch {
            return $null
        }
    }
    return $null
}

function Start-DeviceAuth {
    Write-Status "Starting device authorization..."

    try {
        $response = Invoke-RestMethod -Uri "$ApiUrl/api/v1/bff/auth/device" `
            -Method Post `
            -ContentType "application/json" `
            -ErrorAction Stop

        if (-not $response.success) {
            Write-Status "Authentication initiation failed: $($response.error)" -Type "Error"
            return $null
        }

        return $response.data
    } catch {
        Write-Status "Failed to start device authorization: $_" -Type "Error"
        return $null
    }
}

function Wait-ForAuth {
    param(
        [string]$DeviceCode,
        [string]$UserCode,
        [string]$VerificationUri,
        [int]$ExpiresIn = 300,
        [int]$Interval = 5
    )

    $browserUrl = "$ConsoleUrl/device?code=$UserCode"

    # Try to open browser
    Write-Host ""
    try {
        Start-Process $browserUrl
        Write-Host "    " -NoNewline
        Write-Host "Authenticating... browser opened automatically." -ForegroundColor Green
    } catch {
        Write-Host "    " -NoNewline
        Write-Host "Authenticating... please open browser manually." -ForegroundColor Yellow
    }
    Write-Host ""

    $startTime = Get-Date
    $detailedShown = $false
    $pollInterval = $Interval

    while (((Get-Date) - $startTime).TotalSeconds -lt $ExpiresIn) {
        $elapsed = ((Get-Date) - $startTime).TotalSeconds

        # Show detailed instructions after 15 seconds
        if ($elapsed -ge 15 -and -not $detailedShown) {
            $detailedShown = $true
            Write-Host ""
            Write-Host "    " -NoNewline
            Write-Host "If browser didn't open automatically:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    1. Open this URL: " -NoNewline
            Write-Host $browserUrl -ForegroundColor Green
            Write-Host ""
            Write-Host "    2. If prompted, enter code: " -NoNewline
            Write-Host $UserCode -ForegroundColor Green -BackgroundColor DarkGray
            Write-Host ""
            Write-Host "    Code expires in $([math]::Floor($ExpiresIn / 60)) minutes"
            Write-Host ""
        }

        Start-Sleep -Seconds $pollInterval

        try {
            $body = @{ device_code = $DeviceCode } | ConvertTo-Json
            $tokenResponse = Invoke-RestMethod -Uri "$ApiUrl/api/v1/bff/auth/token" `
                -Method Post `
                -ContentType "application/json" `
                -Body $body `
                -ErrorAction Stop

            if ($tokenResponse.success -and $tokenResponse.data.access_token) {
                Write-Host ""
                Write-Status "Authentication successful!" -Type "Success"
                return $tokenResponse.data.access_token
            }

            switch ($tokenResponse.error) {
                "authorization_pending" {
                    Write-Host "." -NoNewline
                }
                "slow_down" {
                    $pollInterval++
                    Write-Host "." -NoNewline
                }
                "expired_token" {
                    Write-Host ""
                    Write-Status "Code expired. Please restart installation." -Type "Warning"
                    return $null
                }
                "access_denied" {
                    Write-Host ""
                    Write-Status "Authorization denied." -Type "Warning"
                    return $null
                }
                default {
                    Write-Host "." -NoNewline
                }
            }
        } catch {
            Write-Host "." -NoNewline
        }
    }

    Write-Host ""
    Write-Status "Authentication timed out" -Type "Warning"
    return $null
}

function New-ApiKey {
    param([string]$JwtToken)

    Write-Status "Setting up API key..."

    $hostname = $env:COMPUTERNAME
    $platform = "Windows"
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }

    $body = @{
        cli_token = $JwtToken
        device_name = "$hostname ($platform $arch)"
        device_hostname = $hostname
        device_platform = $platform
        device_arch = $arch
        force_new = $true
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "$ApiUrl/api/v1/bff/developer/api-key" `
            -Method Post `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop

        if ($response.success -and $response.data) {
            $apiKey = $response.data.api_key
            $apiEndpoint = $response.data.api_endpoint
            if (-not $apiEndpoint) { $apiEndpoint = $ApiUrl }

            if ($apiKey) {
                # Create config directory
                if (-not (Test-Path $ConfigDir)) {
                    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
                }

                # Save config WITH the API key (stored in config file)
                # Windows user profile permissions protect the file adequately
                # Include console_url for PR environments where it differs from production
                $config = @{
                    api_endpoint = $apiEndpoint
                    console_url = $ConsoleUrl
                    developer_api_key = $apiKey
                    monitor_poll_interval = 1.0
                    configured_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                }

                # Write config file safely (handles permission issues)
                $jsonContent = $config | ConvertTo-Json
                Write-ConfigFile -FilePath $ConfigFile -Content $jsonContent

                # Set file permissions (mark as hidden)
                Set-ConfigFilePermissions -FilePath $ConfigFile | Out-Null

                Write-Status "New API key created and saved" -Type "Success"
                Write-Detail "Config file: $ConfigFile"
                Write-Detail "Endpoint: $apiEndpoint"
                return $true
            } else {
                $keyPrefix = $response.data.key_prefix
                Write-Status "An existing API key was found ($keyPrefix...)" -Type "Warning"
                Write-Detail "For security, the full key is only shown at creation time."
                Write-Detail "Get your key from: $ConsoleUrl/admin/devices"
                return $false
            }
        } else {
            $errorMsg = $response.error
            if (-not $errorMsg) { $errorMsg = "Unknown error" }
            Write-Status "API key creation failed: $errorMsg" -Type "Error"
            Write-Detail "Configure later with: bluebear configure"
            return $false
        }
    } catch {
        Write-Status "Could not set up API key: $_" -Type "Warning"
        Write-Detail "Configure later with: bluebear configure"
        return $false
    }
}

function Get-BlueBearBinary {
    # DEN-750: Downloads the single unified BlueBear binary
    # Downloads from: bluebear/v{version}/windows-x86_64/bluebear-windows-x86_64.exe.zip
    param(
        [string]$JwtToken
    )

    $platform = "windows-x86_64"
    $binaryName = "bluebear-$platform.exe"
    $zipName = "$binaryName.zip"
    $checksumName = "$zipName.sha256"

    # Handle "latest" version specially - don't prefix with "v"
    $versionPath = if ($Version -eq "latest") { "latest" } else { "v$Version" }
    $downloadUrl = "$ApiUrl/api/v1/bff/download/bluebear/$versionPath/$platform/$zipName"
    $checksumUrl = "$ApiUrl/api/v1/bff/download/bluebear/$versionPath/$platform/$checksumName"
    $zipPath = Join-Path $env:TEMP $zipName
    $checksumPath = Join-Path $env:TEMP $checksumName
    $extractPath = Join-Path $env:TEMP "bluebear-extract"

    Write-Status "Downloading BlueBear..."

    try {
        $headers = @{ "Authorization" = "Bearer $JwtToken" }

        # Download the binary zip
        Invoke-WebRequest -Uri $downloadUrl `
            -OutFile $zipPath `
            -Headers $headers `
            -ErrorAction Stop

        if ((Get-Item $zipPath).Length -lt 1000) {
            throw "Downloaded file too small"
        }

        # Download and verify SHA256 checksum
        try {
            Invoke-WebRequest -Uri $checksumUrl `
                -OutFile $checksumPath `
                -Headers $headers `
                -ErrorAction Stop

            # Read expected checksum (format: "hash  filename" or just "hash")
            $expectedChecksum = (Get-Content $checksumPath -Raw).Trim().Split()[0].ToLower()

            # Calculate actual checksum
            $actualChecksum = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()

            if ($expectedChecksum -ne $actualChecksum) {
                Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $checksumPath -Force -ErrorAction SilentlyContinue
                throw "SHA256 checksum verification failed! Expected: $expectedChecksum, Got: $actualChecksum. The download may have been tampered with."
            }

            Write-Detail "SHA256 checksum verified"
            Remove-Item -Path $checksumPath -Force -ErrorAction SilentlyContinue
        } catch [System.Net.WebException] {
            # Checksum file not available - warn but continue (for backwards compatibility)
            Write-Status "Warning: SHA256 checksum not available for verification" -Type "Warning"
        }

        # Extract zip
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }

        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        # Find extracted content (handles both direct and nested extraction)
        $extractedDir = Get-ChildItem -Path $extractPath -Directory | Select-Object -First 1
        if ($extractedDir) {
            $sourcePath = $extractedDir.FullName
        } else {
            $sourcePath = $extractPath
        }

        # Copy files to install directory
        Copy-Item -Path "$sourcePath\*" -Destination $InstallDir -Recurse -Force

        # Rename platform-specific binary to environment-specific name
        # Production: bluebear.exe, PR: bluebear-pr-{N}.exe
        $platformBinary = Join-Path $InstallDir "bluebear-$platform.exe"
        $exeName = if ($Environment) { "bluebear-$Environment.exe" } else { "bluebear.exe" }
        $standardBinary = Join-Path $InstallDir $exeName
        if (Test-Path $platformBinary) {
            Move-Item -Path $platformBinary -Destination $standardBinary -Force
        }

        # Cleanup
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue

        Write-Status "Downloaded BlueBear binary" -Type "Success"
        return $true
    } catch {
        Write-Status "Failed to download BlueBear: $_" -Type "Error"
        return $false
    }
}

function Copy-UninstallScript {
    # Bundle uninstall script with the installation (version-matched)
    # This ensures users always have an uninstaller that matches their installed version
    Write-Status "Bundling uninstall script..."

    # Determine executable name based on environment
    $exeName = if ($Environment) { "bluebear-$Environment.exe" } else { "bluebear.exe" }

    $uninstallPath = Join-Path $InstallDir "uninstall.ps1"
    $uninstallContent = @"
# BlueBear Windows Uninstaller (bundled with installation)
# Run: bluebear-uninstall
#      or: powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\BlueBear\uninstall.ps1"

param([switch]`$KeepConfig, [switch]`$Force)

`$ErrorActionPreference = "Stop"
`$InstallDir = Join-Path `$env:LOCALAPPDATA "BlueBear"
`$BinDir = Join-Path `$InstallDir "bin"
`$ConfigDir = "$ConfigDir"

# Change to user's home directory to avoid "path not found" errors
# when uninstall deletes the current working directory
Set-Location `$env:USERPROFILE

Write-Host ""
Write-Host "BlueBear Windows Uninstaller" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path `$InstallDir)) {
    Write-Host "==> BlueBear is not installed" -ForegroundColor Yellow
    exit 0
}

if (-not `$Force) {
    `$confirm = Read-Host "Are you sure you want to uninstall BlueBear? (y/N)"
    if (`$confirm -ne "y" -and `$confirm -ne "Y") {
        Write-Host "==> Uninstall cancelled"
        exit 0
    }
}

# Run bluebear disable to clean up hooks and daemon
`$bluebearExe = Join-Path `$InstallDir "$exeName"
if (Test-Path `$bluebearExe) {
    Write-Host "==> Running BlueBear cleanup..." -ForegroundColor Cyan
    try { & `$bluebearExe disable 2>&1 | ForEach-Object { Write-Host "    `$_" -ForegroundColor Gray } } catch {}
}

# Stop any remaining processes
Write-Host "==> Stopping BlueBear processes..." -ForegroundColor Cyan
Get-Process -Name "bluebear*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove from PATH
Write-Host "==> Removing from PATH..." -ForegroundColor Cyan
`$path = [Environment]::GetEnvironmentVariable("PATH", "User")
`$newPath = (`$path -split ";" | Where-Object { `$_ -ne `$BinDir -and `$_ }) -join ";"
[Environment]::SetEnvironmentVariable("PATH", `$newPath, "User")

# Remove PowerShell completion
Write-Host "==> Removing PowerShell completion..." -ForegroundColor Cyan
try {
    `$profileDir = Split-Path -Parent `$PROFILE
    # Remove completion files
    Get-ChildItem -Path `$profileDir -Filter "bluebear*.completion.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    # Clean profile
    if (Test-Path `$PROFILE) {
        `$content = Get-Content `$PROFILE -Raw -ErrorAction SilentlyContinue
        if (`$content) {
            `$newContent = `$content -replace '(?m)^\s*# BlueBear CLI completion\s*\r?\n\s*if \(Test-Path "[^"]*bluebear[^"]*\.completion\.ps1"\) \{ \. "[^"]*" \}\s*\r?\n?', ''
            if (`$newContent -ne `$content) { [System.IO.File]::WriteAllText(`$PROFILE, `$newContent) }
        }
    }
} catch {}

# Remove startup scripts
Write-Host "==> Removing startup scripts..." -ForegroundColor Cyan
`$startupFolder = Join-Path `$env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
Remove-Item "`$startupFolder\BlueBear*.vbs" -Force -ErrorAction SilentlyContinue

# Remove installation directory
Write-Host "==> Removing installation directory..." -ForegroundColor Cyan
Remove-Item -Path `$InstallDir -Recurse -Force -ErrorAction SilentlyContinue

# Remove config directory
if (-not `$KeepConfig) {
    Write-Host "==> Removing configuration..." -ForegroundColor Cyan
    Remove-Item -Path `$ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==> BlueBear has been uninstalled" -ForegroundColor Green
Write-Host ""
"@

    Set-Content -Path $uninstallPath -Value $uninstallContent -Encoding UTF8
    Write-Status "Bundled uninstall script" -Type "Success"
}

function New-WrapperScripts {
    # DEN-750: Creates wrapper scripts for the unified binary
    # PR environments use env-suffixed names (bluebear-pr-478, bluebear-pr-478-uninstall)
    Write-Status "Creating wrapper scripts..."

    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    # Determine names based on environment
    $exeBaseName = if ($Environment) { "bluebear-$Environment" } else { "bluebear" }

    # Create main wrapper that calls the binary directly
    $mainWrapperPath = Join-Path $BinDir "$exeBaseName.bat"
    $mainWrapperContent = @"
@echo off
"%LOCALAPPDATA%\BlueBear\$exeBaseName.exe" %*
"@
    Set-Content -Path $mainWrapperPath -Value $mainWrapperContent -Encoding ASCII

    # Create uninstall wrapper that runs the bundled uninstall script
    # Note: The 2>nul suppresses "system cannot find the path specified" errors that occur
    # when the batch file is deleted during uninstall (the uninstall still succeeds)
    $uninstallWrapperPath = Join-Path $BinDir "$exeBaseName-uninstall.bat"
    $uninstallWrapperContent = @"
@echo off
powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\BlueBear\uninstall.ps1" %* 2>nul
exit /b 0
"@
    Set-Content -Path $uninstallWrapperPath -Value $uninstallWrapperContent -Encoding ASCII

    Write-Status "Created wrapper scripts" -Type "Success"
}

function Add-ToPath {
    Write-Status "Adding BlueBear to PATH..."

    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -split ";" -contains $BinDir) {
        Write-Detail "Already in PATH"
        return
    }

    $newPath = "$currentPath;$BinDir"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")

    # Also update current session
    $env:PATH = "$env:PATH;$BinDir"

    Write-Status "Added to PATH" -Type "Success"
    Write-Detail "You may need to restart your terminal for PATH changes to take effect"
}

function Save-InstallInfo {
    # DEN-750: Simplified for single binary - no longer tracks individual clients

    # Load existing config or create new
    $config = @{}
    if (Test-Path $ConfigFile) {
        try {
            # PowerShell 5.1 compatible: convert PSCustomObject to hashtable
            $json = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            $config = @{}
            $json.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }
        } catch {
            $config = @{}
        }
    }

    $config["version"] = $Version
    $config["platform"] = "windows-x86_64"
    $config["install_type"] = "powershell"
    $config["install_dir"] = $InstallDir

    # Write config file safely (handles permission issues)
    $jsonContent = $config | ConvertTo-Json
    Write-ConfigFile -FilePath $ConfigFile -Content $jsonContent

    # Set restrictive file permissions (current user only)
    Set-ConfigFilePermissions -FilePath $ConfigFile | Out-Null
}

function Install-PowerShellCompletion {
    # Install PowerShell completion script to user's profile directory
    # This enables tab completion for bluebear commands in PowerShell
    param([string]$ExePath, [string]$ExeBaseName)

    Write-Status "Installing PowerShell completion..."

    try {
        # Generate completion script
        $completionScript = & $ExePath completion powershell 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Detail "Could not generate completion script"
            return
        }

        # Get PowerShell profile directory (not the profile script itself)
        $profileDir = Split-Path -Parent $PROFILE

        # Create profile directory if it doesn't exist
        if (-not (Test-Path $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }

        # Save completion script to a separate file
        $completionFile = Join-Path $profileDir "$ExeBaseName.completion.ps1"
        $completionScript | Set-Content -Path $completionFile -Encoding UTF8

        # Check if profile exists and if it already sources the completion
        $profileContent = ""
        if (Test-Path $PROFILE) {
            $profileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
        }

        $sourceCommand = ". `"$completionFile`""

        if ($profileContent -notmatch [regex]::Escape($completionFile)) {
            # Add sourcing command to profile
            $profileAddition = @"

# BlueBear CLI completion
if (Test-Path "$completionFile") { $sourceCommand }
"@

            Add-Content -Path $PROFILE -Value $profileAddition -Encoding UTF8
            Write-Status "PowerShell completion installed" -Type "Success"
            Write-Detail "Completion will be available in new PowerShell sessions"
            Write-Detail "Or run: . `"$completionFile`""
        } else {
            Write-Detail "PowerShell completion already configured"
        }
    } catch {
        Write-Detail "Could not install PowerShell completion: $_"
    }
}

# Main installation flow
function Install-BlueBear {
    Write-Host ""
    Write-Host "BlueBear Windows Installer" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""

    # Validate API and Console URLs before proceeding
    if (-not (Test-ValidUrl -Url $ApiUrl -Name "API")) {
        Write-Host ""
        Write-Host "Installation aborted due to invalid API URL." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-ValidUrl -Url $ConsoleUrl -Name "Console")) {
        Write-Host ""
        Write-Host "Installation aborted due to invalid Console URL." -ForegroundColor Red
        exit 1
    }

    # Check for existing config
    $existingConfig = Test-ExistingConfig
    if ($existingConfig) {
        Write-Status "Found existing BlueBear configuration"
        # Safely truncate API key for display (handle short/empty keys)
        $apiKeyPreview = if ($existingConfig.developer_api_key.Length -gt 8) {
            "$($existingConfig.developer_api_key.Substring(0, 8))..."
        } elseif ($existingConfig.developer_api_key.Length -gt 0) {
            "$($existingConfig.developer_api_key.Substring(0, [Math]::Min(4, $existingConfig.developer_api_key.Length)))***"
        } else {
            "(empty)"
        }
        Write-Detail "API Key: $apiKeyPreview"
        Write-Detail "Endpoint: $($existingConfig.api_endpoint)"
        Write-Host ""
        Write-Host "    Existing credentials will be preserved."
        Write-Host ""
    }

    Write-Status "BlueBear Authentication"
    Write-Host ""
    Write-Host "    Quick authentication required for download..."
    Write-Host ""

    # Start OAuth device flow
    $authData = Start-DeviceAuth
    if (-not $authData) {
        Write-Status "Failed to start authentication" -Type "Error"
        Write-Host ""
        Write-Host "Please try again, or manually configure:" -ForegroundColor Yellow
        Write-Host "  1. Visit: $ConsoleUrl/settings"
        Write-Host "  2. Copy your API key"
        Write-Host "  3. After install, run: bluebear configure --api-key YOUR_KEY"
        exit 1
    }

    # Wait for user to authenticate
    # Use PowerShell 5.1 compatible syntax (no ?? operator)
    $expiresIn = if ($authData.expires_in) { $authData.expires_in } else { 300 }
    $interval = if ($authData.interval) { $authData.interval } else { 5 }

    $jwtToken = Wait-ForAuth `
        -DeviceCode $authData.device_code `
        -UserCode $authData.user_code `
        -VerificationUri $authData.verification_uri `
        -ExpiresIn $expiresIn `
        -Interval $interval

    if (-not $jwtToken) {
        Write-Status "Authentication failed or timed out" -Type "Error"
        exit 1
    }

    # Create API key if we don't have existing credentials
    if (-not $existingConfig) {
        New-ApiKey -JwtToken $jwtToken | Out-Null
    } else {
        Write-Status "Preserving existing API key configuration"
    }

    Write-Host ""

    # Create installation directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # DEN-750: Download single unified binary
    if (-not (Get-BlueBearBinary -JwtToken $jwtToken)) {
        Write-Status "Failed to download BlueBear binary" -Type "Error"
        exit 1
    }

    # Bundle uninstall script (version-matched)
    Copy-UninstallScript

    # Create wrapper scripts
    New-WrapperScripts

    # Add to PATH unless disabled
    if (-not $NoAddToPath) {
        Add-ToPath
    }

    # Save installation info
    Save-InstallInfo

    # Install PowerShell completion
    $bluebearExe = Join-Path $InstallDir $exeName
    Install-PowerShellCompletion -ExePath $bluebearExe -ExeBaseName $exeBaseName

    # DEN-750: Run bluebear enable to set up the daemon service
    # Determine executable name based on environment
    $exeName = if ($Environment) { "bluebear-$Environment.exe" } else { "bluebear.exe" }
    $exeBaseName = if ($Environment) { "bluebear-$Environment" } else { "bluebear" }

    Write-Status "Setting up BlueBear daemon..."
    $bluebearExe = Join-Path $InstallDir $exeName
    try {
        & $bluebearExe enable 2>&1 | ForEach-Object { Write-Detail $_ }
        Write-Status "BlueBear daemon enabled and started" -Type "Success"
    } catch {
        Write-Status "Failed to set up daemon: $_" -Type "Warning"
        Write-Detail "You can manually start the daemon with: $exeBaseName enable"
    }

    # Ask user if they want to ingest existing history
    Write-Host ""
    Write-Host "Would you like to ingest existing Claude and Cursor history? [Y/n] " -NoNewline
    $response = Read-Host
    $response = $response.Trim().ToLower()

    if ($response -eq "" -or $response -eq "y" -or $response -eq "yes") {
        Write-Status "Starting history ingestion in background..."

        # Run ingest-history in background for both clients
        # Write script to temp file to avoid quoting/escaping issues with -Command
        $tempScript = Join-Path $env:TEMP "bluebear-ingest-$([guid]::NewGuid().ToString('N').Substring(0,8)).ps1"
        @"
`$exe = '$bluebearExe'
& `$exe ingest-history claude
& `$exe ingest-history cursor
Remove-Item -Path '$tempScript' -Force -ErrorAction SilentlyContinue
"@ | Set-Content -Path $tempScript -Encoding UTF8

        Start-Process powershell -ArgumentList "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", $tempScript -WindowStyle Hidden

        Write-Status "History ingestion running in background" -Type "Success"
    } else {
        Write-Detail "Skipped. You can run later with:"
        Write-Detail "  $exeBaseName ingest-history claude"
        Write-Detail "  $exeBaseName ingest-history cursor"
    }

    Write-Host ""
    Write-Status "BlueBear installation complete!" -Type "Success"
    Write-Host ""
    Write-Host "    To uninstall: " -NoNewline
    Write-Host "$exeBaseName-uninstall" -ForegroundColor Yellow
    Write-Host ""
}

# Run installation
Install-BlueBear
