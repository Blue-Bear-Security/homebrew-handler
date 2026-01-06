# BlueBear Windows Installer
# DEN-275: PowerShell installer script with OAuth device flow authentication
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
$ConfigDir = Join-Path $env:USERPROFILE ".bluebear"
$ConfigFile = Join-Path $ConfigDir "config"

# Version - will be replaced by CI/CD for production releases
# For PR environments, extract from API URL (e.g., api-pr-317 -> pr-317)
$Version = "0.4.23"

# Detect PR version from API URL if not replaced by CI/CD
if ($Version -eq "__VERSION__") {
    if ($ApiUrl -match "api-pr-(\d+)") {
        $Version = "pr-$($Matches[1])"
    } else {
        # Fallback to latest for production when version not set
        $Version = "latest"
    }
}

# Client configurations
# Note: Codex is not available on Windows (macOS/Linux only)
$Clients = @{
    "claude" = @{
        Name = "Claude Code"
        S3Path = "claude-hooks"
    }
    "copilot" = @{
        Name = "GitHub Copilot"
        S3Path = "copilot-hooks"
    }
    "cursor" = @{
        Name = "Cursor IDE"
        S3Path = "cursor-hooks"
    }
}

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
            Write-Detail "Configure later with: bluebear <client> configure"
            return $false
        }
    } catch {
        Write-Status "Could not set up API key: $_" -Type "Warning"
        Write-Detail "Configure later with: bluebear <client> configure"
        return $false
    }
}

function Get-ClientBinary {
    param(
        [string]$Client,
        [string]$JwtToken
    )

    $clientInfo = $Clients[$Client]
    $s3Path = $clientInfo.S3Path
    $platform = "windows-x86_64"
    $binaryName = "bluebear-$Client-hooks-$platform.exe"
    $zipName = "$binaryName.zip"
    $checksumName = "$zipName.sha256"

    # Handle "latest" version specially - don't prefix with "v"
    $versionPath = if ($Version -eq "latest") { "latest" } else { "v$Version" }
    $downloadUrl = "$ApiUrl/api/v1/bff/download/$s3Path/$versionPath/$platform/$zipName"
    $checksumUrl = "$ApiUrl/api/v1/bff/download/$s3Path/$versionPath/$platform/$checksumName"
    $zipPath = Join-Path $env:TEMP $zipName
    $checksumPath = Join-Path $env:TEMP $checksumName
    $extractPath = Join-Path $env:TEMP "bluebear-$Client-extract"
    $clientDir = Join-Path $InstallDir "bluebear-$Client"

    Write-Status "Downloading $($clientInfo.Name)..."

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

        # Create client directory
        if (Test-Path $clientDir) {
            Remove-Item -Path $clientDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $clientDir -Force | Out-Null

        # Copy files
        Copy-Item -Path "$sourcePath\*" -Destination $clientDir -Recurse -Force

        # Rename platform-specific binary to standard name
        # e.g., bluebear-claude-hooks-windows-x86_64.exe -> bluebear-hooks.exe
        $platformBinary = Join-Path $clientDir $binaryName
        $standardBinary = Join-Path $clientDir "bluebear-hooks.exe"
        if (Test-Path $platformBinary) {
            Move-Item -Path $platformBinary -Destination $standardBinary -Force
        }

        # Cleanup
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue

        Write-Status "Installed $($clientInfo.Name)" -Type "Success"
        return $true
    } catch {
        Write-Status "Failed to download $($clientInfo.Name): $_" -Type "Error"
        return $false
    }
}

function New-WrapperScripts {
    Write-Status "Creating wrapper scripts..."

    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $installedClients = @()

    # Create individual client wrappers
    foreach ($client in $Clients.Keys) {
        $clientDir = Join-Path $InstallDir "bluebear-$client"
        $binaryPath = Join-Path $clientDir "bluebear-hooks.exe"

        if (Test-Path $binaryPath) {
            $wrapperPath = Join-Path $BinDir "bluebear-$client.bat"
            $wrapperContent = @"
@echo off
"%LOCALAPPDATA%\BlueBear\bluebear-$client\bluebear-hooks.exe" %*
"@
            Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII
            $installedClients += $client
        }
    }

    # Create unified 'bluebear' wrapper
    $mainWrapperPath = Join-Path $BinDir "bluebear.bat"
    $mainWrapperContent = @'
@echo off
setlocal enabledelayedexpansion

REM BlueBear unified CLI wrapper
REM Usage: bluebear <client> <command> [options]

if "%1"=="" goto :show_help
if "%1"=="-h" goto :show_help
if "%1"=="--help" goto :show_help
if "%1"=="-v" goto :show_version
if "%1"=="--version" goto :show_version
if "%1"=="migrate-key" goto :migrate_key
if "%1"=="version" goto :version_subcommand

set CLIENT=%1

REM Build remaining args (skip first arg) - %* doesn't update after shift
set ARGS=
shift
:build_args
if "%1"=="" goto :check_client
set ARGS=!ARGS! %1
shift
goto :build_args

:check_client
REM Route to client binary (codex not supported on Windows)
if "%CLIENT%"=="claude" goto :run_client
if "%CLIENT%"=="copilot" goto :run_client
if "%CLIENT%"=="cursor" goto :run_client
if "%CLIENT%"=="codex" (
    echo Error: Codex is not supported on Windows. >&2
    exit /b 1
)

echo Error: Unknown client: %CLIENT% >&2
echo Supported clients: claude, copilot, cursor >&2
exit /b 1

:run_client
set INSTALL_DIR=%LOCALAPPDATA%\BlueBear
set BINARY=%INSTALL_DIR%\bluebear-%CLIENT%\bluebear-hooks.exe
if not exist "%BINARY%" (
    echo Error: Client '%CLIENT%' is not installed. >&2
    echo Expected: %BINARY% >&2
    exit /b 1
)
"%BINARY%" !ARGS!
exit /b !errorlevel!

:migrate_key
REM Try any installed client for migrate-key
set INSTALL_DIR=%LOCALAPPDATA%\BlueBear
for %%c in (claude copilot cursor) do (
    set BINARY=!INSTALL_DIR!\bluebear-%%c\bluebear-hooks.exe
    if exist "!BINARY!" (
        "!BINARY!" migrate-key
        exit /b !errorlevel!
    )
)
echo Error: No BlueBear clients installed. >&2
exit /b 1

:version_subcommand
REM Handle 'bluebear version' and 'bluebear version --check'
if "%2"=="--check" goto :version_check
goto :show_version

:version_check
REM Try any installed client for version check
set INSTALL_DIR=%LOCALAPPDATA%\BlueBear
for %%c in (claude copilot cursor) do (
    set BINARY=!INSTALL_DIR!\bluebear-%%c\bluebear-hooks.exe
    if exist "!BINARY!" (
        "!BINARY!" version --check
        exit /b !errorlevel!
    )
)
echo Error: No BlueBear clients installed. >&2
exit /b 1

:show_help
echo BlueBear - Unified CLI for AI Agent Governance
echo.
echo Usage: bluebear ^<client^> ^<command^> [options]
echo.
echo Supported clients:
echo   claude    Claude Code / Anthropic
echo   copilot   GitHub Copilot
echo   cursor    Cursor IDE
echo.
echo Commands vary by client. Common commands include:
echo   enable        Enable hooks for the client
echo   disable       Disable hooks for the client
echo   configure     Configure API credentials
echo   status        Show integration status
echo.
echo Global commands:
echo   migrate-key   Migrate API key to Windows Credential Manager
echo   version       Show version (--check for updates)
echo.
echo Examples:
echo   bluebear claude enable         Enable Claude Code hooks
echo   bluebear claude disable        Disable Claude Code hooks
echo   bluebear cursor enable         Enable Cursor IDE hooks
echo   bluebear migrate-key           Migrate API key
echo   bluebear version --check       Check for updates
echo.
echo Options:
echo   -h, --help     Show this help message
echo   -v, --version  Show version information
echo.
echo Documentation: https://app.bluebearsecurity.io/docs
exit /b 0

:show_version
'@
    # Replace docs URL with configured console URL and append version line
    $mainWrapperContent = $mainWrapperContent -replace 'https://app.bluebearsecurity.io/docs', "$ConsoleUrl/docs"
    $mainWrapperContent += "`necho bluebear version $Version`nexit /b 0"

    Set-Content -Path $mainWrapperPath -Value $mainWrapperContent -Encoding ASCII

    Write-Status "Created wrapper scripts" -Type "Success"
    return $installedClients
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
    param([string[]]$InstalledClients)

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

    $config["installed_clients"] = $InstalledClients
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
        Write-Host "  3. After install, run: bluebear <client> configure --api-key YOUR_KEY"
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

    # Download all clients
    $installedClients = @()
    foreach ($client in $Clients.Keys) {
        if (Get-ClientBinary -Client $client -JwtToken $jwtToken) {
            $installedClients += $client
        }
    }

    if ($installedClients.Count -eq 0) {
        Write-Status "No clients were installed" -Type "Error"
        exit 1
    }

    # Create wrapper scripts
    $installedClients = New-WrapperScripts

    # Add to PATH unless disabled
    if (-not $NoAddToPath) {
        Add-ToPath
    }

    # Save installation info
    Save-InstallInfo -InstalledClients $installedClients

    # Print success message
    Write-Host ""
    Write-Status "BlueBear installation complete!" -Type "Success"
    Write-Host ""
    Write-Host "    Clients are installed but " -NoNewline
    Write-Host "not yet enabled" -ForegroundColor Green -NoNewline
    Write-Host "."
    Write-Host ""
    Write-Host "    " -NoNewline
    Write-Host "Enable each client:" -ForegroundColor Green
    foreach ($client in $installedClients) {
        Write-Host "      bluebear $client enable"
    }
    Write-Host ""
    Write-Host "    To disable:"
    foreach ($client in $installedClients) {
        Write-Host "      bluebear $client disable"
    }
    Write-Host ""
    Write-Host "    Your configuration is stored in: $ConfigFile"
    Write-Host ""
    Write-Host "    Documentation: $ConsoleUrl/docs"
    Write-Host ""

    if (-not $NoAddToPath) {
        Write-Host "    " -NoNewline
        Write-Host "NOTE: " -ForegroundColor Yellow -NoNewline
        Write-Host "You may need to restart your terminal to use 'bluebear' command."
        Write-Host ""
    }
}

# Run installation
Install-BlueBear
