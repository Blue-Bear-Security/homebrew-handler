# DEPRECATED: This formula template is deprecated in favor of the cask template.
# See blueden.rb.cask.template for the current installation method.
#
# Homebrew formulas run install_name_tool on Mach-O binaries, which breaks
# PyInstaller onedir bundles. Use casks instead:
#   brew install --cask bluebear
#
# ============================================================================
# OLD DOCUMENTATION (kept for reference):
# ============================================================================
# Homebrew formula for BlueBear CLI - AI Coding Agent Governance
# DEN-315: Unified formula with bluebear command wrapper
#
# Installation (DEPRECATED - use cask instead):
#   brew tap Blue-Bear-Security/handler
#   brew install --cask bluebear                    # Recommended
#
# Legacy formula options (no longer supported):
#   brew install bluebear --with claude             # Claude Code only
#   brew install bluebear --with claude,codex       # Claude + Codex
#   brew install bluebear --with all                # Explicitly all clients
#
# Or set environment variable:
#   BLUEDEN_CLIENT=claude,codex brew install bluebear
#
# Usage:
#   bluebear claude enable       # Enable Claude Code hooks
#   bluebear codex enable        # Enable Codex hooks
#   bluebear copilot enable      # Enable Copilot hooks
#   bluebear cursor enable       # Enable Cursor hooks
#
# Supported clients:
# - claude (Claude Code / Anthropic)
# - codex (OpenAI Codex)
# - copilot (GitHub Copilot)
# - cursor (Cursor IDE)
# - gemini (Google Gemini) [coming soon]

require "json"

# DEN-577: Environment configuration for multi-environment support
# These are placeholders replaced by generate-formulas.sh for non-production formulas
BLUEBEAR_ENVIRONMENT = ""  # e.g., "pr-123", "dev", or empty for production
BLUEBEAR_ENV_SUFFIX = BLUEBEAR_ENVIRONMENT.empty? ? "" : "-#{BLUEBEAR_ENVIRONMENT}"
BINARY_PREFIX = "bluebear"  # e.g., "bluebear" or "bluebear-pr-123"

# Custom download strategy that handles OAuth device flow authentication
class BluebearOAuthDownloadStrategy < CurlDownloadStrategy
  def initialize(url, name, version, **meta)
    @api_base = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")
    @console_url = ENV.fetch("BLUEDEN_CONSOLE_URL", "https://app.bluebearsecurity.io")
    # DEN-577: Use environment-specific config directory
    @config_dir = File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}")
    @client_name = meta[:client] || "claude"
    super
  end

  def _fetch(url:, resolved_url:, timeout:)
    FileUtils.mkdir_p(@config_dir)

    auth_token = nil
    auth_type = nil

    # First, check for existing API key (for upgrades - skip OAuth if already configured)
    @existing_config = load_existing_config
    if @existing_config && @existing_config["developer_api_key"] && !@existing_config["developer_api_key"].empty?
      auth_token = @existing_config["developer_api_key"]
      auth_type = 'api_key'
      ohai "Using existing API key for download (upgrade mode)"
      puts ""
      puts "  API Key: #{auth_token[0..15]}..."
      puts "  Endpoint: #{@existing_config["api_endpoint"]}"
      puts ""
    end

    # If no existing API key, run OAuth device flow (fresh install)
    unless auth_token
      ohai "BlueBear OAuth Authentication Required"
      puts ""
      puts "This installation requires authentication with your BlueBear account."
      puts ""

      auth_token = authenticate_device_flow
      auth_type = 'jwt'

      unless auth_token
        raise CurlDownloadStrategyError, <<~EOS
          BlueBear authentication failed or timed out.

          Please try again, or manually configure:
            1. Visit: #{@console_url}/settings
            2. Copy your API key
            3. After install, run: bluebear <client> configure --api-key YOUR_KEY
        EOS
      end
    end

    ohai "Downloading #{@client_name} binary..."
    temporary_path.dirname.mkpath

    curl_args = [
      "-fL",
      "-H", "Authorization: Bearer #{auth_token}",
      "-o", temporary_path.to_s,
      url
    ]

    system_command!("curl", args: curl_args, verbose: verbose?)

    unless temporary_path.exist?
      raise CurlDownloadStrategyError, "Downloaded file not found"
    end

    downloaded_size = temporary_path.size
    ohai "Downloaded #{downloaded_size} bytes"

    if downloaded_size < 1000
      raise CurlDownloadStrategyError, "Download failed - file too small (#{downloaded_size} bytes)"
    end

    # Only set up API key if we used OAuth (fresh install)
    # For upgrades, API key already exists
    if auth_type == 'jwt'
      setup_api_key(auth_token)
    else
      ohai "Preserving existing API key configuration"
    end

    # Save auth token for install phase to download additional binaries
    # Use the auth token (JWT or API key) for consistency
    jwt_cache_file = File.join(@config_dir, ".jwt_cache")
    File.write(jwt_cache_file, auth_token)
    File.chmod(0600, jwt_cache_file)

    # Also save token next to the downloaded file (in Homebrew cache) for install phase access
    # (Homebrew sandbox may block access to ~/.bluebear during install)
    jwt_buildpath_file = "#{temporary_path}.jwt"
    File.write(jwt_buildpath_file, auth_token)
    File.chmod(0600, jwt_buildpath_file)
  end

  private

  def load_existing_config
    # Config is stored directly in @config_dir (~/.bluebear)
    config_file = File.join(@config_dir, "config")
    return nil unless File.exist?(config_file)

    begin
      JSON.parse(File.read(config_file))
    rescue JSON::ParserError
      nil
    end
  end

  def authenticate_device_flow
    require "open3"

    ohai "Starting device authorization..."

    stdout, status = Open3.capture2(
      "curl", "-s", "-X", "POST",
      "#{@api_base}/api/v1/bff/auth/device",
      "-H", "Content-Type: application/json"
    )

    return nil unless status.success?

    begin
      response = JSON.parse(stdout)
    rescue JSON::ParserError
      opoo "Invalid response from authentication server"
      return nil
    end

    unless response["success"]
      opoo "Authentication initiation failed: #{response['error']}"
      return nil
    end

    # Data is nested under 'data' key per response_builder format
    data = response["data"] || {}
    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"] || "#{@console_url}/device"
    verification_uri_complete = data["verification_uri_complete"]
    expires_in = data["expires_in"] || 300

    browser_url = verification_uri_complete || "#{@console_url}/device?code=#{user_code}"

    # Try to open browser automatically
    browser_opened = false
    if OS.mac?
      system "open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    elsif OS.linux? && which("xdg-open")
      system "xdg-open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    end

    # Simple initial message
    $stderr.puts ""
    if browser_opened
      $stderr.puts "  \e[32mAuthenticating... browser opened automatically.\e[0m"
    else
      $stderr.puts "  \e[33mAuthenticating... please open browser manually.\e[0m"
    end
    $stderr.puts ""

    poll_interval = data["interval"] || 5
    max_poll_time = [expires_in, 300].min
    start_time = Time.now
    detailed_message_shown = false

    loop do
      elapsed = Time.now - start_time
      break if elapsed >= max_poll_time

      # Show detailed instructions after 15 seconds if not authenticated
      if elapsed >= 15 && !detailed_message_shown
        detailed_message_shown = true
        $stderr.puts ""
        $stderr.puts "  \e[33mIf browser didn't open automatically:\e[0m"
        $stderr.puts ""
        $stderr.puts "  1. Open this URL: \e[32m#{browser_url}\e[0m"
        $stderr.puts ""
        $stderr.puts "  2. If prompted, enter code: \e[1m\e[32m#{user_code}\e[0m"
        $stderr.puts ""
        $stderr.puts "  Code expires in #{expires_in / 60} minutes"
        $stderr.puts ""
      end

      sleep poll_interval

      token_stdout, token_status = Open3.capture2(
        "curl", "-s", "-X", "POST",
        "#{@api_base}/api/v1/bff/auth/token",
        "-H", "Content-Type: application/json",
        "-d", JSON.generate({ device_code: device_code })
      )

      next unless token_status.success?

      begin
        token_response = JSON.parse(token_stdout)
      rescue JSON::ParserError
        next
      end

      token_data = token_response["data"] || {}
      if token_response["success"] && token_data["access_token"]
        puts ""
        ohai "Authentication successful!"
        return token_data["access_token"]
      end

      error = token_response["error"]
      case error
      when "authorization_pending"
        print "."
        $stdout.flush
      when "slow_down"
        poll_interval += 1
        print "."
        $stdout.flush
      when "expired_token"
        puts ""
        opoo "Code expired. Please restart installation."
        return nil
      when "access_denied"
        puts ""
        opoo "Authorization denied."
        return nil
      else
        print "."
        $stdout.flush
      end
    end

    puts ""
    opoo "Authentication timed out"
    nil
  end

  def setup_api_key(jwt_token)
    ohai "Setting up API key..."

    # Collect device info for identification
    hostname = `hostname`.strip rescue "unknown"
    platform = OS.mac? ? "macOS" : "Linux"
    arch = Hardware::CPU.arm? ? "ARM64" : "x86_64"

    # Use request body for token (API Gateway strips Authorization header for non-authorizer routes)
    request_body = {
      cli_token: jwt_token,
      device_name: "#{hostname} (#{platform} #{arch})",
      device_hostname: hostname,
      device_platform: platform,
      device_arch: arch,
      force_new: true  # Always create a new key on install (revokes existing if any)
    }

    stdout, status = Open3.capture2(
      "curl", "-s", "-X", "POST",
      "#{@api_base}/api/v1/bff/developer/api-key",
      "-H", "Content-Type: application/json",
      "-d", JSON.generate(request_body)
    )

    unless status.success?
      opoo "Could not set up API key automatically. Configure later with: bluebear <client> configure"
      return
    end

    begin
      response = JSON.parse(stdout)
    rescue JSON::ParserError
      opoo "Invalid response when setting up API key"
      return
    end

    if response["success"] && response["data"]
      data = response["data"]
      api_key = data["api_key"]  # Only present for new keys
      key_prefix = data["key_prefix"]
      created = data["created"]
      # Use api_endpoint from response (data ingestion Lambda URL), fallback to BFF URL
      api_endpoint = data["api_endpoint"] || @api_base

      if api_key
        # Try to store API key in system keychain first
        keychain_stored = store_api_key_in_keychain(api_key)

        # Save config file (without API key if stored in keychain)
        config_file = File.join(@config_dir, "config")
        config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}
        config["api_endpoint"] = api_endpoint
        config["bff_endpoint"] = @api_base  # BFF API URL for version checks and other BFF APIs
        config["monitor_poll_interval"] = 1.0
        config["configured_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        if keychain_stored
          # Remove API key from config file if it exists - it's now in keychain
          config.delete("developer_api_key")
        else
          # Fallback: store in config file if keychain failed
          config["developer_api_key"] = api_key
        end

        File.write(config_file, JSON.pretty_generate(config))
        File.chmod(0600, config_file)

        if keychain_stored
          ohai "New API key created and stored in system keychain"
        else
          ohai "New API key created and saved to config file"
          opoo "Run 'bluebear claude migrate-key' to move it to the system keychain"
        end
      else
        # Existing key found - the full key was only shown at creation time
        # User needs to get their existing key from the console or revoke and create a new one
        opoo "An existing API key was found for your account (#{key_prefix}...)"
        opoo "For security, the full key is only shown at creation time."
        opoo ""
        opoo "To configure, either:"
        opoo "  1. Get your key from: https://app.bluebearsecurity.io/admin/devices"
        opoo "  2. Or revoke the existing key and re-run: brew reinstall bluebear"
        opoo ""
        opoo "Then run: bluebear <client> configure --api-endpoint #{@api_base} --developer-api-key YOUR_KEY"
      end
    else
      # Log the actual error for debugging
      error_msg = response["error"] || response["message"] || "Unknown error"
      error_code = response["error_code"] || response.dig("data", "error") || "UNKNOWN"
      opoo "API key creation failed: #{error_code} - #{error_msg}"
      opoo "Response: #{stdout[0..500]}" if stdout && !stdout.empty?
      opoo "Configure later with: bluebear <client> configure"
    end
  end

  def store_api_key_in_keychain(api_key)
    # Store API key in system keychain for secure storage
    # Returns true if successful, false otherwise

    if OS.mac?
      # macOS: Use security command to store in Keychain
      # Delete existing entry first (ignore errors if it doesn't exist)
      system("security", "delete-generic-password",
             "-s", "bluebear",
             "-a", "developer_api_key",
             [:out, :err] => "/dev/null")

      # Add new entry - use stdin to avoid exposing API key in process listings
      # The -w flag without an argument reads the password from stdin
      _, status = Open3.capture2(
        "security", "add-generic-password",
        "-s", "bluebear",
        "-a", "developer_api_key",
        "-w",
        "-U",  # Update if exists
        stdin_data: api_key
      )

      if status.success?
        ohai "API key stored in macOS Keychain"
        return true
      else
        opoo "Could not store API key in macOS Keychain"
        return false
      end

    elsif OS.linux? && which("secret-tool")
      # Linux: Use secret-tool (libsecret) if available
      # This works with GNOME Keyring, KWallet, etc.
      stdin_data = api_key

      _, status = Open3.capture2(
        "secret-tool", "store",
        "--label", "BlueBear Developer API Key",
        "service", "bluebear",
        "username", "developer_api_key",
        stdin_data: stdin_data
      )

      if status.success?
        ohai "API key stored in Linux Secret Service"
        return true
      else
        opoo "Could not store API key in Linux Secret Service"
        return false
      end

    else
      # No supported keychain available
      return false
    end
  end
end

class Bluebear < Formula
  desc "BlueBear - Secure AI coding agent governance for Claude, Codex, Copilot, and more"
  homepage "https://bluebearsecurity.io"
  version "0.4.27"

  # API base URL for downloads
  API_BASE = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")

  # Supported clients configuration
  CLIENTS = {
    "claude" => {
      name: "Claude Code",
      desc: "Anthropic Claude Code hooks",
      sha256: {
        "macos-arm64" => "715fb12205934bb2a4ab41af9c33987b79ab7471da4ba8a94cd35d2aec9df7ee",
        "macos-x86_64" => "00412dfc6a1d4057632da6e632656388cc34cc2475d0bc62e08d25f54dc2ae6a",
        "linux-arm64" => "515cf21c0864775bfa198e4710b7456b74fff266f4951a10282a4f50b7d94125",
        "linux-x86_64" => "e4ad84975379e408429fe2259c2280b2d8b08a5c04d3ab15d84fcdb82ab22362",
      }
    },
    "codex" => {
      name: "OpenAI Codex",
      desc: "OpenAI Codex CLI hooks",
      sha256: {
        "macos-arm64" => "c12b652a91827ab1a154b00705e80be2ff50f32a468c2e03db1c7809acbce6f1",
        "macos-x86_64" => "5de4bf728ebd334daccbdd9df6e43e54d04bff35436834dd129cb011a899eeb0",
        "linux-arm64" => "4697b21238b3065607b2a5b27417af47e84c2599b746c605fa163a3e3d2a25ae",
        "linux-x86_64" => "dc85151fdf607990c7cdfe1f6d7f5b1450845a7ec489cf366814621b2453bbef",
      }
    },
    "copilot" => {
      name: "GitHub Copilot",
      desc: "GitHub Copilot CLI hooks",
      sha256: {
        "macos-arm64" => "6effd90fcc01c9fca5c7c96cd30b4b47648cbb523ef6dda4d7787065cdf18519",
        "macos-x86_64" => "1695e57ad6de82559510dc8f21969d84f0a64fc245e0e9d25cce69a20e6cdf9d",
        "linux-arm64" => "d478db6b656781785e0c993ed94951ff61432ca15e3526422d61264dfd77b762",
        "linux-x86_64" => "9eadc8cda32962a563736f7ba8e0979c70b403f296df99d757e9c51208d968c7",
      }
    },
    "cursor" => {
      name: "Cursor IDE",
      desc: "Cursor IDE hooks",
      sha256: {
        "macos-arm64" => "e0e09c73604e34d0ab083bb73df5793f8ca217000a91a6c9a0c8028254ffc6a3",
        "macos-x86_64" => "8b91cf2cc8bb88a92e11688cf5b5935e2091a623a0081c9432d7e7692331dbd2",
        "linux-arm64" => "86053800d55cb8cd00c275460a95a58e868dfc9102b4bbc73bf2894e3054888d",
        "linux-x86_64" => "6eedfc50a4859fe3b4875eee430c3dd708fe0935c7ea7777a505afdfe4810353",
      }
    },
    # Future clients (uncomment when ready):
    # "gemini" => {
    #   name: "Google Gemini",
    #   desc: "Google Gemini CLI hooks",
    #   sha256: {
    #     "macos-arm64" => "__SHA256_GEMINI_MACOS_ARM64__",
    #     "macos-x86_64" => "__SHA256_GEMINI_MACOS_X86_64__",
    #     "linux-arm64" => "__SHA256_GEMINI_LINUX_ARM64__",
    #     "linux-x86_64" => "__SHA256_GEMINI_LINUX_X86_64__",
    #   }
    # },
  }.freeze

  # Formula option for client selection
  # Usage: brew install bluebear --with claude,codex,copilot,cursor
  #        brew install bluebear --with all
  #        BLUEDEN_CLIENT=claude,codex brew install bluebear
  option "with", "Comma-separated list of clients to install (claude,codex,copilot,cursor) or 'all'"

  def self.platform_key
    if OS.mac?
      Hardware::CPU.arm? ? "macos-arm64" : "macos-x86_64"
    elsif OS.linux?
      Hardware::CPU.arm? ? "linux-arm64" : "linux-x86_64"
    else
      raise "Unsupported platform"
    end
  end

  def self.selected_clients
    clients = []

    # Check --with option (comma-separated list)
    if build.with?("with")
      with_value = ARGV.value("with") || ""
      if with_value.downcase == "all"
        clients = CLIENTS.keys
      else
        requested = with_value.split(",").map(&:strip).map(&:downcase)
        clients = requested.select { |c| CLIENTS.key?(c) }
      end
    end

    # Check environment variable as fallback
    if clients.empty? && ENV["BLUEDEN_CLIENT"]
      env_value = ENV["BLUEDEN_CLIENT"]
      if env_value.downcase == "all"
        clients = CLIENTS.keys
      else
        env_clients = env_value.split(",").map(&:strip).map(&:downcase)
        clients = env_clients.select { |c| CLIENTS.key?(c) }
      end
    end

    # Default to all clients if nothing selected
    clients = CLIENTS.keys if clients.empty?

    clients.uniq
  end

  # Primary URL (first selected client)
  def self.primary_client
    selected_clients.first
  end

  # DEN-352: Download tarball for faster startup (onedir PyInstaller build)
  url "#{API_BASE}/api/v1/bff/download/#{primary_client}-hooks/v0.4.27/#{platform_key}/bluebear-#{primary_client}-hooks-#{platform_key}.tar.gz",
    using: BluebearOAuthDownloadStrategy,
    client: primary_client
  sha256 CLIENTS[primary_client][:sha256][platform_key]

  # DEN-352: Skip Homebrew's library path fixing for PyInstaller bundles
  # PyInstaller bundles have their own library structure that shouldn't be modified
  skip_clean :all

  def install
    selected = self.class.selected_clients
    platform = self.class.platform_key

    # DEN-352: Try to install binaries to ~/.bluebear/lib/ (outside Homebrew cellar)
    # This avoids Homebrew's dylib relocation which fails on PyInstaller bundles
    # because they have insufficient Mach-O header padding for install_name_tool.
    #
    # However, Homebrew's sandbox may prevent writing outside the cellar.
    # If that happens, fall back to installing in pkgshare (cellar) which
    # will show a harmless warning but still work correctly.
    #
    # IMPORTANT: Use Etc.getpwuid to get the real user's home directory.
    # Homebrew sets HOME to a temporary .brew_home directory during builds.
    #
    # DEN-577: Use environment-specific lib directory for multi-env support
    require "etc"
    real_home = Etc.getpwuid.dir
    lib_dir = Pathname.new("#{real_home}/.bluebear#{BLUEBEAR_ENV_SUFFIX}/lib")

    # Try to create external lib directory, fall back to cellar if sandbox blocks it
    use_external_lib = false
    begin
      lib_dir.mkpath
      use_external_lib = true
      ohai "Using external lib directory: #{lib_dir}"
    rescue Errno::EPERM, Errno::EACCES => e
      ohai "Cannot write to external directory (sandbox), using cellar instead"
      use_external_lib = false
    end

    ohai "Installing BlueBear for: #{selected.map { |c| CLIENTS[c][:name] }.join(', ')}"

    # Install the primary client (already downloaded and extracted via main URL)
    primary = selected.first

    # Find the extracted directory (tarball extracts to bluebear-{client}-hooks-{platform}/)
    # Note: Homebrew may strip the top-level directory from tarballs, so we handle both cases
    primary_dir = Dir["bluebear-*-hooks-*"].find { |d| File.directory?(d) }

    if use_external_lib
      # EXTERNAL LIB MODE: Install to ~/.bluebear/lib/, symlink in cellar
      # This avoids the dylib relocation warning
      target_lib_dir = lib_dir/"bluebear-#{primary}"
      FileUtils.rm_rf(target_lib_dir)
      target_lib_dir.mkpath

      if primary_dir
        FileUtils.cp_r("#{primary_dir}/.", target_lib_dir)
      elsif File.exist?("bluebear-hooks") && File.directory?("_internal")
        FileUtils.cp("bluebear-hooks", target_lib_dir/"bluebear-hooks")
        FileUtils.cp_r("_internal", target_lib_dir/"_internal")
      elsif File.exist?("bluebear-hooks")
        FileUtils.cp("bluebear-hooks", target_lib_dir/"bluebear-hooks")
      end

      # Create symlinks in pkgshare (Homebrew skips symlinks during relocation)
      pkgshare_client_dir = pkgshare/"bluebear-#{primary}"
      pkgshare_client_dir.mkpath
      main_binary = target_lib_dir/"bluebear-hooks"
      internal_dir = target_lib_dir/"_internal"

      if main_binary.exist?
        main_binary.chmod(0755)
        ln_sf main_binary, pkgshare_client_dir/"bluebear-hooks"
        ln_sf internal_dir, pkgshare_client_dir/"_internal" if internal_dir.directory?

        # DEN-577: Wrapper uses environment-specific paths and binary names
        wrapper_name = "#{BINARY_PREFIX}-#{primary}"
        (bin/wrapper_name).write <<~BASH
          #!/bin/bash
          export BLUEBEAR_ENVIRONMENT="#{BLUEBEAR_ENVIRONMENT}"
          exec "$HOME/.bluebear#{BLUEBEAR_ENV_SUFFIX}/lib/bluebear-#{primary}/bluebear-hooks" "$@"
        BASH
        (bin/wrapper_name).chmod(0755)
        ohai "✓ Installed #{wrapper_name}"
      else
        opoo "Could not find binary for #{primary}"
      end
    else
      # CELLAR MODE: Install directly to pkgshare (may show dylib warning)
      target_dir = pkgshare/"bluebear-#{primary}"

      if primary_dir
        pkgshare.install primary_dir => "bluebear-#{primary}"
      elsif File.exist?("bluebear-hooks") && File.directory?("_internal")
        target_dir.mkpath
        cp "bluebear-hooks", target_dir/"bluebear-hooks"
        cp_r "_internal", target_dir/"_internal"
      elsif File.exist?("bluebear-hooks")
        target_dir.mkpath
        cp "bluebear-hooks", target_dir/"bluebear-hooks"
      else
        opoo "Could not find extracted content for #{primary}"
        ohai "Contents of buildpath:"
        Dir["*"].each { |f| puts "  #{f} (#{File.directory?(f) ? 'dir' : 'file'})" }
      end

      main_binary = target_dir/"bluebear-hooks"
      if main_binary.exist?
        main_binary.chmod(0755)
        # DEN-577: Use environment-specific binary name
        wrapper_name = "#{BINARY_PREFIX}-#{primary}"
        (bin/wrapper_name).write <<~BASH
          #!/bin/bash
          export BLUEBEAR_ENVIRONMENT="#{BLUEBEAR_ENVIRONMENT}"
          exec "#{pkgshare}/bluebear-#{primary}/bluebear-hooks" "$@"
        BASH
        (bin/wrapper_name).chmod(0755)
        ohai "✓ Installed #{wrapper_name}"
      else
        opoo "Could not find binary for #{primary}"
      end
    end

    # Download and install additional client binaries
    require "open3"
    api_base = API_BASE

    # Read authentication token from various sources:
    # 1. JWT/API key token from download phase (saved to .jwt file or .jwt_cache)
    # 2. Existing API key from config (for reinstall scenarios where fetch is skipped)
    auth_token = nil

    # IMPORTANT: Homebrew sets a temporary HOME during install phase, so we must
    # use the actual user's home directory from /etc/passwd via Etc.getpwuid
    # This works on macOS and Linux (both POSIX-compliant)
    require 'etc'
    real_home = Etc.getpwuid&.dir || Dir.home

    # Look for JWT file in buildpath, cache, or real home's .bluebear/.jwt_cache
    # DEN-577: Use environment-specific config directory
    possible_jwt_paths = [
      Dir["#{buildpath}/../*.jwt"].first,
      Dir["#{HOMEBREW_CACHE}/**/*.jwt"].first,
      File.join(real_home, ".bluebear#{BLUEBEAR_ENV_SUFFIX}/.jwt_cache")
    ].compact.uniq

    possible_jwt_paths.each do |path|
      if path && File.exist?(path)
        auth_token = File.read(path).strip
        ohai "Found auth token at #{path}"
        break
      end
    end

    # Fallback: read API key from config (for reinstall scenarios where fetch is skipped)
    # DEN-577: Use environment-specific config directory
    if auth_token.nil? || auth_token.empty?
      config_path = File.join(real_home, ".bluebear#{BLUEBEAR_ENV_SUFFIX}/config")
      if File.exist?(config_path)
        begin
          config = JSON.parse(File.read(config_path))
          if config["developer_api_key"] && !config["developer_api_key"].empty?
            auth_token = config["developer_api_key"]
            ohai "Using API key from #{config_path} for downloads"
          end
        rescue JSON::ParserError
          # Skip invalid config files
        end
      end
    end

    selected.drop(1).each do |client|
      ohai "Downloading #{CLIENTS[client][:name]} binary..."

      # DEN-352: Download tarball instead of raw binary
      download_url = "#{api_base}/api/v1/bff/download/#{client}-hooks/v#{version}/#{platform}/bluebear-#{client}-hooks-#{platform}.tar.gz"
      tarball_path = "#{buildpath}/bluebear-#{client}-hooks-#{platform}.tar.gz"

      if auth_token && !auth_token.empty?
        stdout, status = Open3.capture2(
          "curl", "-fsSL",
          "-H", "Authorization: Bearer #{auth_token}",
          "-o", tarball_path,
          download_url
        )

        if status.success? && File.exist?(tarball_path) && File.size(tarball_path) > 1000
          # Verify SHA256 of tarball
          expected_sha = CLIENTS[client][:sha256][platform]
          actual_sha = Digest::SHA256.file(tarball_path).hexdigest

          if actual_sha == expected_sha
            # Extract tarball
            system "tar", "-xzf", tarball_path, "-C", buildpath.to_s

            # Find extracted content
            client_dir = Dir["#{buildpath}/bluebear-#{client}-hooks-*"].find { |d| File.directory?(d) }
            extracted_binary = buildpath/"bluebear-hooks"
            extracted_internal = buildpath/"_internal"

            if use_external_lib
              # EXTERNAL LIB MODE
              target_lib_dir = lib_dir/"bluebear-#{client}"
              FileUtils.rm_rf(target_lib_dir)
              target_lib_dir.mkpath

              if client_dir
                FileUtils.cp_r("#{client_dir}/.", target_lib_dir)
              elsif extracted_binary.exist? && extracted_internal.directory?
                FileUtils.cp(extracted_binary, target_lib_dir/"bluebear-hooks")
                FileUtils.cp_r(extracted_internal, target_lib_dir/"_internal")
                rm extracted_binary
                rm_rf extracted_internal
              elsif extracted_binary.exist?
                FileUtils.cp(extracted_binary, target_lib_dir/"bluebear-hooks")
                rm extracted_binary
              else
                opoo "Could not find extracted content for #{client}"
                next
              end

              pkgshare_client_dir = pkgshare/"bluebear-#{client}"
              pkgshare_client_dir.mkpath
              client_binary = target_lib_dir/"bluebear-hooks"
              client_internal = target_lib_dir/"_internal"

              if client_binary.exist?
                client_binary.chmod(0755)
                ln_sf client_binary, pkgshare_client_dir/"bluebear-hooks"
                ln_sf client_internal, pkgshare_client_dir/"_internal" if client_internal.directory?

                # DEN-577: Use environment-specific binary name
                client_wrapper_name = "#{BINARY_PREFIX}-#{client}"
                (bin/client_wrapper_name).write <<~BASH
                  #!/bin/bash
                  export BLUEBEAR_ENVIRONMENT="#{BLUEBEAR_ENVIRONMENT}"
                  exec "$HOME/.bluebear#{BLUEBEAR_ENV_SUFFIX}/lib/bluebear-#{client}/bluebear-hooks" "$@"
                BASH
                (bin/client_wrapper_name).chmod(0755)
                ohai "✓ Installed #{client_wrapper_name}"
              else
                opoo "Could not find binary for #{client}"
              end
            else
              # CELLAR MODE
              target_dir = pkgshare/"bluebear-#{client}"

              if client_dir
                pkgshare.install client_dir => "bluebear-#{client}"
              elsif extracted_binary.exist? && extracted_internal.directory?
                target_dir.mkpath
                cp extracted_binary, target_dir/"bluebear-hooks"
                cp_r extracted_internal, target_dir/"_internal"
                rm extracted_binary
                rm_rf extracted_internal
              elsif extracted_binary.exist?
                target_dir.mkpath
                cp extracted_binary, target_dir/"bluebear-hooks"
                rm extracted_binary
              else
                opoo "Could not find extracted content for #{client}"
                next
              end

              client_binary = target_dir/"bluebear-hooks"
              if client_binary.exist?
                client_binary.chmod(0755)
                # DEN-577: Use environment-specific binary name
                client_wrapper_name = "#{BINARY_PREFIX}-#{client}"
                (bin/client_wrapper_name).write <<~BASH
                  #!/bin/bash
                  export BLUEBEAR_ENVIRONMENT="#{BLUEBEAR_ENVIRONMENT}"
                  exec "#{pkgshare}/bluebear-#{client}/bluebear-hooks" "$@"
                BASH
                (bin/client_wrapper_name).chmod(0755)
                ohai "✓ Installed #{client_wrapper_name}"
              else
                opoo "Could not find binary for #{client}"
              end
            end
          else
            opoo "SHA256 mismatch for #{client}, skipping (expected: #{expected_sha[0..15]}..., got: #{actual_sha[0..15]}...)"
          end
        else
          opoo "Failed to download #{client} tarball, skipping"
        end
      else
        opoo "No authentication token available, skipping #{client} download"
      end
    end

    # Clean up all JWT and temporary files from Homebrew cache
    cleanup_homebrew_cache

    # Create the wrapper script with environment-specific name
    # DEN-577: Use BINARY_PREFIX for the wrapper (bluebear, bluebear-pr-123, etc.)
    wrapper_script = <<~BASH
      #!/bin/bash
      # BlueBear unified CLI wrapper
      # Usage: #{BINARY_PREFIX} <client> <command> [options]
      #        #{BINARY_PREFIX} update
      #        #{BINARY_PREFIX} version [--check]
      #
      # DEN-577: Environment-specific wrapper script

      set -e

      BLUEBEAR_VERSION="#{version}"
      BLUEBEAR_ENVIRONMENT="#{BLUEBEAR_ENVIRONMENT}"
      BINARY_PREFIX="#{BINARY_PREFIX}"
      CONFIG_FILE="$HOME/.bluebear#{BLUEBEAR_ENV_SUFFIX}/config"

      show_help() {
          echo "BlueBear - Unified CLI for AI Agent Governance"
          echo ""
          echo "Usage: bluebear <command> [options]"
          echo "       bluebear <client> <command> [options]"
          echo ""
          echo "Global commands:"
          echo "  update            Update BlueBear to the latest version"
          echo "  version           Show version information for all clients"
          echo "  version --check   Check for available updates"
          echo "  migrate-key       Move API key from config file to system keychain"
          echo ""
          echo "Supported clients:"
          echo "  claude    Claude Code / Anthropic"
          echo "  codex     OpenAI Codex CLI"
          echo "  copilot   GitHub Copilot"
          echo "  cursor    Cursor IDE"
          echo ""
          echo "Client commands:"
          echo "  enable        Enable hooks for the client"
          echo "  disable       Disable hooks for the client"
          echo "  configure     Configure API credentials"
          echo "  status        Show integration status"
          echo "  daemon        Manage the background daemon"
          echo ""
          echo "Examples:"
          echo "  bluebear update                 Update to latest version"
          echo "  bluebear version --check        Check for updates"
          echo "  bluebear migrate-key            Migrate API key to keychain"
          echo "  bluebear uninstall              Prepare for brew uninstall"
          echo "  bluebear claude enable          Enable Claude Code hooks"
          echo "  bluebear claude disable         Disable Claude Code hooks"
          echo "  bluebear codex enable           Enable Codex hooks"
          echo "  bluebear copilot status         Check Copilot status"
          echo ""
          echo "Options:"
          echo "  -h, --help     Show this help message"
          echo "  -v, --version  Show version information"
          echo ""
          echo "For client-specific help:"
          echo "  bluebear <client> --help"
          echo ""
          echo "Documentation: https://app.bluebearsecurity.io/docs"
      }

      show_version() {
          echo "BlueBear CLI v$BLUEBEAR_VERSION"
          echo ""
          echo "Installed clients:"
          for client in claude codex copilot cursor; do
              binary="bluebear-$client"
              if command -v "$binary" &> /dev/null; then
                  client_version=$("$binary" --version 2>/dev/null | head -1 || echo "unknown")
                  echo "  $client: $client_version"
              fi
          done
      }

      check_for_updates() {
          echo "Checking for updates..."
          echo ""

          # Get API key from config
          if [[ ! -f "$CONFIG_FILE" ]]; then
              echo "Error: BlueBear not configured. Run 'bluebear <client> configure' first." >&2
              exit 1
          fi

          API_KEY=$(grep -o '"developer_api_key"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" 2>/dev/null | sed 's/.*"developer_api_key"[[:space:]]*:[[:space:]]*"\\([^"]*\\)"/\\1/')
          BFF_ENDPOINT=$(grep -o '"bff_endpoint"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" 2>/dev/null | sed 's/.*"bff_endpoint"[[:space:]]*:[[:space:]]*"\\([^"]*\\)"/\\1/')

          # Default to production BFF endpoint
          if [[ -z "$BFF_ENDPOINT" ]]; then
              BFF_ENDPOINT="https://api.bluebearsecurity.io"
          fi

          if [[ -z "$API_KEY" ]]; then
              echo "Error: No API key configured. Run 'bluebear <client> configure' first." >&2
              exit 1
          fi

          # Call version check endpoint
          RESPONSE=$(curl -s -w "\\n%{http_code}" \\
              -H "Authorization: Bearer $API_KEY" \\
              -H "X-Client-Version: $BLUEBEAR_VERSION" \\
              -H "X-Client-Name: bluebear" \\
              "$BFF_ENDPOINT/api/v1/bff/version" 2>/dev/null || echo "error")

          HTTP_CODE=$(echo "$RESPONSE" | tail -1)
          BODY=$(echo "$RESPONSE" | sed '$d')

          if [[ "$HTTP_CODE" != "200" ]]; then
              echo "Current version: v$BLUEBEAR_VERSION"
              echo "Unable to check for updates (HTTP $HTTP_CODE)"
              exit 0
          fi

          # Parse response
          LATEST=$(echo "$BODY" | grep -o '"latest_version"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"latest_version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)"/\\1/')
          UPDATE_AVAILABLE=$(echo "$BODY" | grep -o '"update_available"[[:space:]]*:[[:space:]]*[^,}]*' | sed 's/.*://;s/[[:space:]]//g')
          URGENCY=$(echo "$BODY" | grep -o '"update_urgency"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"update_urgency"[[:space:]]*:[[:space:]]*"\\([^"]*\\)"/\\1/')

          echo "Current version: v$BLUEBEAR_VERSION"
          echo "Latest version:  v$LATEST"
          echo ""

          if [[ "$UPDATE_AVAILABLE" == "true" ]]; then
              if [[ "$URGENCY" == "required" ]]; then
                  echo "⚠️  CRITICAL UPDATE REQUIRED!"
                  echo "   Security vulnerability detected. Please update immediately."
              elif [[ "$URGENCY" == "recommended" ]]; then
                  echo "📦 Update recommended"
              else
                  echo "📦 Optional update available"
              fi
              echo ""
              echo "To update, run: brew upgrade bluebear"
          else
              echo "✓ You are running the latest version"
          fi
      }

      do_update() {
          echo "Updating BlueBear..."
          echo ""

          if command -v brew &> /dev/null; then
              brew upgrade bluebear || brew upgrade pr-*-bluebear 2>/dev/null || {
                  echo "BlueBear is already up to date, or no Homebrew formula found."
                  echo ""
                  echo "If you installed from a PR formula, try:"
                  echo "  brew upgrade pr-<NUMBER>-bluebear"
              }
          else
              echo "Error: Homebrew not found. Please update manually." >&2
              exit 1
          fi
      }

      get_client_binary() {
          # DEN-577: Use environment-specific binary names
          case "$1" in
              claude)  echo "${BINARY_PREFIX}-claude" ;;
              codex)   echo "${BINARY_PREFIX}-codex" ;;
              copilot) echo "${BINARY_PREFIX}-copilot" ;;
              cursor)  echo "${BINARY_PREFIX}-cursor" ;;
              *)       echo "" ;;
          esac
      }

      # Handle global commands first
      case "${1:-}" in
          -h|--help) show_help; exit 0 ;;
          -v|--version) show_version; exit 0 ;;
          version)
              if [[ "${2:-}" == "--check" ]]; then
                  check_for_updates
              else
                  show_version
              fi
              exit 0
              ;;
          update) do_update; exit 0 ;;
          uninstall)
              # DEN-577: Prepare for uninstall by disabling all clients
              echo "Preparing BlueBear for uninstall..."
              echo ""
              errors=0
              for client in claude codex copilot cursor; do
                  binary=$(get_client_binary "$client")
                  if command -v "$binary" &> /dev/null; then
                      echo "Disabling $client..."
                      if "$binary" disable 2>/dev/null; then
                          echo "  ✓ $client disabled"
                      else
                          echo "  ✗ Failed to disable $client (may not be enabled)"
                      fi
                  fi
              done
              echo ""
              # DEN-577: Remove config directory on uninstall
              if [[ -d "${CONFIG_DIR}" ]]; then
                  echo "Removing config directory: ${CONFIG_DIR}"
                  rm -rf "${CONFIG_DIR}"
                  echo "  ✓ Config directory removed"
              fi
              echo ""
              echo "All clients disabled. You can now run:"
              echo "  brew uninstall ${BINARY_PREFIX//-/ }"
              exit 0
              ;;
          "") show_help; exit 0 ;;
          migrate-key)
              # Global command - migrate API key from config file to system keychain
              # Try any installed client (all have keyring bundled via PyInstaller)
              # DEN-577: Use environment-specific binary names
              for client in ${BINARY_PREFIX}-claude ${BINARY_PREFIX}-codex ${BINARY_PREFIX}-copilot ${BINARY_PREFIX}-cursor; do
                  if command -v "$client" &> /dev/null; then
                      exec "$client" migrate-key
                  fi
              done
              # Fallback to embedded Python script (requires keyring package)
              # DEN-577: Pass config file path via environment variable
              BLUEBEAR_CONFIG_FILE="$CONFIG_FILE" python3 - <<'PYTHON_SCRIPT'
import json
import os
import sys
from pathlib import Path

# DEN-577: Get environment-specific config path from environment variable
CONFIG_FILE = Path(os.environ.get('BLUEBEAR_CONFIG_FILE', str(Path.home() / '.bluebear' / 'config')))
# DEN-577: Derive service name from config path
# ~/.bluebear/config -> bluebear
# ~/.bluebear-pr-123/config -> bluebear-pr-123
config_dir_name = CONFIG_FILE.parent.name  # .bluebear or .bluebear-pr-123
SERVICE_NAME = config_dir_name.lstrip('.')  # bluebear or bluebear-pr-123
KEY_NAME = 'developer_api_key'

def get_keyring_name():
    try:
        import keyring
        backend = keyring.get_keyring()
        name = type(backend).__name__
        if 'SecretService' in name:
            return 'Linux Secret Service'
        elif 'Keychain' in name or 'macOS' in name.lower():
            return 'macOS Keychain'
        elif 'Windows' in name:
            return 'Windows Credential Manager'
        return name
    except:
        return 'Unknown'

def is_keyring_available():
    try:
        import keyring
        backend = keyring.get_keyring()
        backend_name = type(backend).__name__.lower()
        return 'fail' not in backend_name and 'null' not in backend_name
    except ImportError:
        return False

def get_from_keychain():
    try:
        import keyring
        return keyring.get_password(SERVICE_NAME, KEY_NAME)
    except:
        return None

def set_in_keychain(api_key):
    try:
        import keyring
        keyring.set_password(SERVICE_NAME, KEY_NAME, api_key)
        return True
    except:
        return False

def main():
    if not is_keyring_available():
        print("✗ System keychain is not available on this system", file=sys.stderr)
        print("  Your API key will remain in the config file.")
        print("  Install 'keyring' package: pip install keyring")
        sys.exit(1)

    # Check if already in keychain
    if get_from_keychain():
        print("✓ API key is already stored in the system keychain")
        print(f"  Backend: {get_keyring_name()}")
        # Check if also in config file and remove it
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                if KEY_NAME in config:
                    config.pop(KEY_NAME)
                    with open(CONFIG_FILE, 'w') as f:
                        json.dump(config, f, indent=2)
                    print("  Removed duplicate key from config file")
            except:
                pass
        sys.exit(0)

    # Check if in config file
    if not CONFIG_FILE.exists():
        print("✗ No API key found to migrate", file=sys.stderr)
        print("  Run 'bluebear <client> configure' to set up your API key")
        sys.exit(1)

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except:
        print("✗ Could not read config file", file=sys.stderr)
        sys.exit(1)

    api_key = config.get(KEY_NAME)
    if not api_key:
        print("✗ No API key found in config file to migrate", file=sys.stderr)
        print("  Run 'bluebear <client> configure' to set up your API key")
        sys.exit(1)

    # Migrate to keychain
    print(f"Migrating API key to {get_keyring_name()}...")
    if set_in_keychain(api_key):
        # Remove from config file
        config.pop(KEY_NAME)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        print("✓ API key migrated successfully!")
        print("  Your API key has been moved to the system keychain.")
        print("  The plaintext key has been removed from ~/.bluebear/config")
    else:
        print("✗ Migration failed", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
PYTHON_SCRIPT
              ;;
      esac

      # Handle client commands
      client="$1"
      shift

      binary=$(get_client_binary "$client")
      if [[ -z "$binary" ]]; then
          echo "Error: Unknown client or command: $client" >&2
          echo "Run 'bluebear --help' for usage information." >&2
          exit 1
      fi

      if ! command -v "$binary" &> /dev/null; then
          echo "Error: Client '$client' is not installed. Binary '$binary' not found." >&2
          exit 1
      fi

      if [[ $# -eq 0 ]]; then
          exec "$binary" --help
      fi

      exec "$binary" "$@"
    BASH

    # Strip leading 6 spaces from each line (Ruby's <<~ doesn't work due to embedded Python with 0 indentation)
    # DEN-577: Use environment-specific binary name
    (bin/BINARY_PREFIX).write(wrapper_script.gsub(/^      /, ''))
    (bin/BINARY_PREFIX).chmod(0755)

    # Save installed clients to config
    # DEN-577: Use environment-specific config directory
    config_dir = Pathname.new(File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}"))
    config_dir.mkpath
    config_file = config_dir / "config"

    config = config_file.exist? ? JSON.parse(config_file.read) : {}
    config["installed_clients"] = selected
    config["version"] = version.to_s
    config["platform"] = platform

    config_file.write(JSON.pretty_generate(config))
    config_file.chmod(0600)

    # Note: All clients share the same config at ~/.bluebear/config
    # The OAuth flow writes to this location, so all clients are automatically configured
  end

  private

  def cleanup_homebrew_cache
    # Clean up JWT files from buildpath (next to downloaded binaries)
    Dir["#{buildpath}/../*.jwt"].each { |f| FileUtils.rm_f(f) }

    # Clean up any .jwt files in Homebrew cache directory
    Dir["#{HOMEBREW_CACHE}/**/*.jwt"].each { |f| FileUtils.rm_f(f) }

    # Clean up .jwt_cache file in config directory
    # DEN-577: Use environment-specific config directory
    jwt_cache_file = File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}/.jwt_cache")
    FileUtils.rm_f(jwt_cache_file) if File.exist?(jwt_cache_file)

    # Clean up any blueden-related temp files in Homebrew cache
    Dir["#{HOMEBREW_CACHE}/**/blueden-*"].each do |f|
      # Only remove files, not directories, and only temp/partial files
      FileUtils.rm_f(f) if File.file?(f) && !f.end_with?(".rb")
    end

    ohai "Cleaned up temporary files from Homebrew cache"
  end

  public

  def caveats
    selected = self.class.selected_clients
    config_file = File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}/config")
    config_exists = File.exist?(config_file)

    client_list = selected.map { |c| "  - #{CLIENTS[c][:name]} (#{BINARY_PREFIX} #{c})" }.join("\n")

    # Build setup instructions based on selected clients
    enable_instructions = []
    disable_instructions = []
    if selected.include?("claude")
      enable_instructions << "          #{BINARY_PREFIX} claude enable"
      disable_instructions << "          #{BINARY_PREFIX} claude disable"
    end
    if selected.include?("cursor")
      enable_instructions << "          #{BINARY_PREFIX} cursor enable"
      disable_instructions << "          #{BINARY_PREFIX} cursor disable"
    end
    if selected.include?("copilot")
      enable_instructions << "          #{BINARY_PREFIX} copilot enable"
      disable_instructions << "          #{BINARY_PREFIX} copilot disable"
    end
    if selected.include?("codex")
      enable_instructions << "          #{BINARY_PREFIX} codex enable"
      disable_instructions << "          #{BINARY_PREFIX} codex disable"
    end
    setup_section = enable_instructions.empty? ? "" : "\n        Enable each client:\n#{enable_instructions.join("\n")}\n\n        To disable:\n#{disable_instructions.join("\n")}\n"

    if config_exists
      <<~EOS
        BlueBear has been installed!

        \e[32m✓ Authentication complete!\e[0m

        Installed clients:
#{client_list}
#{setup_section}
        Your configuration is stored in: #{config_file}

        Quick commands:
          #{BINARY_PREFIX} claude status   # Check Claude status
          #{BINARY_PREFIX} --help          # View all commands

        Before uninstalling (REQUIRED on Linux):
          #{BINARY_PREFIX} uninstall       # Disables all clients and removes config

        Documentation: https://docs.bluebearsecurity.io
      EOS
    else
      <<~EOS
        BlueBear has been installed!

        \e[33m⚠ Authentication may not have completed.\e[0m

        Installed clients:
#{client_list}

        To configure manually:
          1. Visit: https://app.bluebearsecurity.io/admin/devices
          2. Copy your API key
          3. Run: #{BINARY_PREFIX} <client> configure --api-key YOUR_KEY
#{setup_section}
        Quick commands:
          #{BINARY_PREFIX} claude status   # Check Claude status
          #{BINARY_PREFIX} --help          # View all commands

        Before uninstalling (REQUIRED on Linux):
          #{BINARY_PREFIX} uninstall       # Disables all clients and removes config

        Documentation: https://docs.bluebearsecurity.io
      EOS
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/#{BINARY_PREFIX} --version")
  end
end
