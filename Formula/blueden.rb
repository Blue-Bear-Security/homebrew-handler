# Homebrew formula for BlueDen CLI - AI Coding Agent Governance
# Unified formula supporting multiple AI coding agent integrations
#
# Installation:
#   brew tap Blue-Bear-Security/homebrew-handler
#   brew install blueden                           # All clients (default)
#   brew install blueden --with claude             # Claude Code only
#   brew install blueden --with claude,codex       # Claude + Codex
#   brew install blueden --with all                # Explicitly all clients
#
# Or set environment variable:
#   BLUEDEN_CLIENT=claude,codex brew install blueden
#
# Supported clients:
# - claude (Claude Code / Anthropic)
# - codex (OpenAI Codex)
# - copilot (GitHub Copilot)
# - cursor (Cursor IDE)
# - gemini (Google Gemini) [coming soon]

require "json"

# Custom download strategy that handles OAuth device flow authentication
class BluedenOAuthDownloadStrategy < CurlDownloadStrategy
  def initialize(url, name, version, **meta)
    @api_base = ENV.fetch("BLUEDEN_API_URL", "https://n93alh7z95.execute-api.us-east-1.amazonaws.com/prod")
    @console_url = ENV.fetch("BLUEDEN_CONSOLE_URL", "https://app.bluebearsecurity.io/console")
    @config_dir = File.expand_path("~/.config/blueden")
    @client_name = meta[:client] || "claude"
    super
  end

  def _fetch(url:, resolved_url:, timeout:)
    FileUtils.mkdir_p(@config_dir)

    ohai "BlueDen OAuth Authentication Required"
    puts ""
    puts "This installation requires authentication with your BlueDen account."
    puts ""

    jwt_token = authenticate_device_flow

    unless jwt_token
      raise CurlDownloadStrategyError, <<~EOS
        BlueDen authentication failed or timed out.

        Please try again, or manually configure:
          1. Visit: #{@console_url}/settings
          2. Copy your API key
          3. After install, run: blueden configure --api-key YOUR_KEY
      EOS
    end

    ohai "Downloading #{@client_name} binary..."
    temporary_path.dirname.mkpath

    curl_args = [
      "-fL",
      "-H", "Authorization: Bearer #{jwt_token}",
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

    setup_api_key(jwt_token)

    # Save JWT token for install phase to download additional binaries
    jwt_cache_file = File.join(@config_dir, ".jwt_cache")
    File.write(jwt_cache_file, jwt_token)
    File.chmod(0600, jwt_cache_file)

    # Also save JWT token next to the downloaded file for install phase access
    # (Homebrew sandbox may block access to ~/.config during install)
    jwt_buildpath_file = "#{temporary_path}.jwt"
    File.write(jwt_buildpath_file, jwt_token)
    File.chmod(0600, jwt_buildpath_file)
  end

  private

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

    $stderr.puts ""
    $stderr.puts "  To authenticate, please:"
    $stderr.puts ""
    $stderr.puts "  1. Open this URL in your browser:"
    $stderr.puts "     \e[32m#{verification_uri}\e[0m"
    $stderr.puts ""
    $stderr.puts "  2. Enter this code when prompted:"
    $stderr.puts ""
    $stderr.puts "     \e[1m\e[32m┌─────────────────┐\e[0m"
    $stderr.puts "     \e[1m\e[32m│    #{user_code}    │\e[0m"
    $stderr.puts "     \e[1m\e[32m└─────────────────┘\e[0m"
    $stderr.puts ""
    $stderr.puts "  Code expires in #{expires_in / 60} minutes"
    $stderr.puts ""

    browser_url = verification_uri_complete || "#{@console_url}/device?code=#{user_code}"
    browser_opened = false

    if OS.mac?
      system "open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    elsif OS.linux? && which("xdg-open")
      system "xdg-open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    end

    $stderr.puts browser_opened ? "  \e[32mBrowser opened automatically.\e[0m" : "  \e[33mPlease open the URL above manually.\e[0m"
    $stderr.puts ""
    $stderr.puts "Waiting for authentication..."

    poll_interval = data["interval"] || 5
    max_poll_time = [expires_in, 300].min
    start_time = Time.now

    loop do
      elapsed = Time.now - start_time
      break if elapsed >= max_poll_time

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
      opoo "Could not set up API key automatically. Configure later with: blueden configure"
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
        # New key created - save it
        # Write to ~/.config/blueden/config.json (formula's config location)
        config_file = File.join(@config_dir, "config.json")
        config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}
        config["api_key"] = api_key
        config["api_url"] = api_endpoint  # Use data ingestion URL
        config["configured_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        File.write(config_file, JSON.pretty_generate(config))
        File.chmod(0600, config_file)

        # Also write to ~/.blueden/config (clients' config location) in their expected format
        client_config_dir = File.expand_path("~/.blueden")
        FileUtils.mkdir_p(client_config_dir)
        client_config_file = File.join(client_config_dir, "config")
        client_config = {
          "api_endpoint" => api_endpoint,  # Use data ingestion URL from response
          "developer_api_key" => api_key,
          "monitor_poll_interval" => 1.0
        }
        File.write(client_config_file, JSON.pretty_generate(client_config))
        File.chmod(0600, client_config_file)

        ohai "New API key created and saved (endpoint: #{api_endpoint})"
      else
        # Existing key found - the full key was only shown at creation time
        # User needs to get their existing key from the console or revoke and create a new one
        opoo "An existing API key was found for your account (#{key_prefix}...)"
        opoo "For security, the full key is only shown at creation time."
        opoo ""
        opoo "To configure, either:"
        opoo "  1. Get your key from: https://app.bluebearsecurity.io/admin/api-keys"
        opoo "  2. Or revoke the existing key and re-run: brew reinstall blueden"
        opoo ""
        opoo "Then run: blueden configure --api-endpoint #{@api_base} --developer-api-key YOUR_KEY"
      end
    else
      # Log the actual error for debugging
      error_msg = response["error"] || response["message"] || "Unknown error"
      error_code = response["error_code"] || response.dig("data", "error") || "UNKNOWN"
      opoo "API key creation failed: #{error_code} - #{error_msg}"
      opoo "Response: #{stdout[0..500]}" if stdout && !stdout.empty?
      opoo "Configure later with: blueden configure"
    end
  end
end

class Blueden < Formula
  desc "BlueDen - Secure AI coding agent governance for Claude, Codex, Copilot, and more"
  homepage "https://bluebearsecurity.io"
  version "0.4.2"

  # API base URL for downloads
  API_BASE = ENV.fetch("BLUEDEN_API_URL", "https://n93alh7z95.execute-api.us-east-1.amazonaws.com/prod")

  # Supported clients configuration
  CLIENTS = {
    "claude" => {
      name: "Claude Code",
      desc: "Anthropic Claude Code hooks",
      sha256: {
        "macos-arm64" => "31dffb802034998773beb261a04825779380be3da0dfe505899c998c052bc13c",
        "macos-x86_64" => "16cf44e825e91576b7dbfb8a7bda06067e5e09081159f0f3527d385d9a5c372e",
        "linux-arm64" => "acbe7f379c5a22424d06bb18ef27c34a6015e894187cf6a771d50e03ff31f075",
        "linux-x86_64" => "3f1a6264a6a4e48298e31c94a1ee5557a6dcbeb60d5fb0a685879be58419229d",
      }
    },
    "codex" => {
      name: "OpenAI Codex",
      desc: "OpenAI Codex CLI hooks",
      sha256: {
        "macos-arm64" => "f40c1b68991da636b4affc13fab74ee30d0ca6d35096079acec119cd1ef8ca06",
        "macos-x86_64" => "1ba7f43a1f870a437afee419c48d2bc5c8cead6c9ce09a2110e7dd61e6b94118",
        "linux-arm64" => "999d7df13ed2ba452ed922d4732938ef7d12106237305c5611749661ff5c6b86",
        "linux-x86_64" => "00252fe5decde92e7220cfbb7166ca0b1da7926d07fdadf606762801edc13cf5",
      }
    },
    "copilot" => {
      name: "GitHub Copilot",
      desc: "GitHub Copilot CLI hooks",
      sha256: {
        "macos-arm64" => "f9dfecae74fc40449de1a9265e8c16e40dc00f1382531deca8a282632e4b4ef5",
        "macos-x86_64" => "3e28588d67c4d488e51113066b442be1fd5157aef3498668e9c35c7ffd33070a",
        "linux-arm64" => "3d4235b3373dcd54ddaf351d510e95cc2a605c5a3b200ec510eab9e9ba516cb2",
        "linux-x86_64" => "45a62f8c0d6f481b53ded43e16250eaa4482b5ec65711582b4c1440f681390e6",
      }
    },
    "cursor" => {
      name: "Cursor IDE",
      desc: "Cursor IDE hooks",
      sha256: {
        "macos-arm64" => "3958bd1897d87299f1dc41e7fac5193f5c332d4230792ee149a8503ffd554ecf",
        "macos-x86_64" => "7b5eb12753129f54172cda2291fe1d7e6035284a05a19a1834044163d29a78e5",
        "linux-arm64" => "d1fb8fb5f20507addc8655d356d5ff98e4e498a396bfee252f4b9d86bee4de68",
        "linux-x86_64" => "5c2f2aea2c6ee0f0570c0a173ca80c5c6b42398ddce06445985db13e48b6d65a",
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
  # Usage: brew install blueden --with claude,codex,copilot,cursor
  #        brew install blueden --with all
  #        BLUEDEN_CLIENT=claude,codex brew install blueden
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

  url "#{API_BASE}/api/v1/bff/download/#{primary_client}-hooks/v0.4.2/#{platform_key}/blueden-#{primary_client}-hooks-#{platform_key}",
    using: BluedenOAuthDownloadStrategy,
    client: primary_client
  sha256 CLIENTS[primary_client][:sha256][platform_key]

  def install
    # The regex was matching against commented-out placeholders in gemini section

    selected = self.class.selected_clients
    platform = self.class.platform_key

    ohai "Installing BlueDen for: #{selected.map { |c| CLIENTS[c][:name] }.join(', ')}"

    # Install the primary binary (already downloaded via main URL)
    primary = selected.first
    primary_binary = Dir["blueden-*-hooks-*"].first
    bin.install primary_binary => "blueden-#{primary}"

    # Download and install additional client binaries
    require "open3"
    api_base = API_BASE

    # Read JWT token from cache file (saved during download phase)
    # Try multiple possible locations since sandbox environments may have different HOME
    jwt_token = nil

    # First, try to find JWT file in buildpath (most reliable in sandbox)
    jwt_in_buildpath = Dir["#{buildpath}/../*.jwt"].first || Dir["#{HOMEBREW_CACHE}/**/*.jwt"].first

    possible_jwt_paths = [
      jwt_in_buildpath,
      File.expand_path("~/.config/blueden/.jwt_cache"),
      File.join(ENV['HOME'] || '', ".config/blueden/.jwt_cache"),
      "/home/#{ENV['USER']}/.config/blueden/.jwt_cache",
      "#{Dir.home}/.config/blueden/.jwt_cache"
    ].compact.uniq

    possible_jwt_paths.each do |path|
      if path && File.exist?(path)
        jwt_token = File.read(path).strip
        ohai "Found JWT token at #{path}"
        break
      end
    end

    selected.drop(1).each do |client|
      ohai "Downloading #{CLIENTS[client][:name]} binary..."

      download_url = "#{api_base}/api/v1/bff/download/#{client}-hooks/v#{version}/#{platform}/blueden-#{client}-hooks-#{platform}"
      binary_path = "#{buildpath}/blueden-#{client}-hooks-#{platform}"

      if jwt_token && !jwt_token.empty?
        stdout, status = Open3.capture2(
          "curl", "-fsSL",
          "-H", "Authorization: Bearer #{jwt_token}",
          "-o", binary_path,
          download_url
        )

        if status.success? && File.exist?(binary_path) && File.size(binary_path) > 1000
          # Verify SHA256
          expected_sha = CLIENTS[client][:sha256][platform]
          actual_sha = Digest::SHA256.file(binary_path).hexdigest

          if actual_sha == expected_sha
            File.chmod(0755, binary_path)
            bin.install binary_path => "blueden-#{client}"
            ohai "✓ Installed blueden-#{client}"
          else
            opoo "SHA256 mismatch for #{client}, skipping (expected: #{expected_sha[0..15]}..., got: #{actual_sha[0..15]}...)"
          end
        else
          opoo "Failed to download #{client} binary, skipping"
        end
      else
        opoo "JWT token not found, skipping #{client} download"
      end
    end

    # Clean up JWT cache files
    possible_jwt_paths.each do |path|
      FileUtils.rm_f(path) if path && File.exist?(path)
    end
    # Also clean up any .jwt files in cache directory
    Dir["#{HOMEBREW_CACHE}/**/*.jwt"].each { |f| FileUtils.rm_f(f) }

    # Create main 'blueden' symlink to primary client
    bin.install_symlink "blueden-#{primary}" => "blueden"

    # Save installed clients to config
    config_dir = Pathname.new(File.expand_path("~/.config/blueden"))
    config_dir.mkpath
    config_file = config_dir / "config.json"

    config = config_file.exist? ? JSON.parse(config_file.read) : {}
    config["installed_clients"] = selected
    config["version"] = version.to_s
    config["platform"] = platform

    config_file.write(JSON.pretty_generate(config))
    config_file.chmod(0600)

    # Note: All clients share the same config at ~/.blueden/config
    # The OAuth flow writes to this location, so all clients are automatically configured
  end

  def caveats
    selected = self.class.selected_clients
    config_file = File.expand_path("~/.config/blueden/config.json")
    config_exists = File.exist?(config_file)

    client_list = selected.map { |c| "  - #{CLIENTS[c][:name]} (blueden-#{c})" }.join("\n")

    if config_exists
      <<~EOS
        BlueDen has been installed!

        \e[32m✓ Authentication complete!\e[0m

        Installed clients:
#{client_list}

        Your configuration is stored in: #{config_file}

        Quick commands:
          blueden test             # Test the connection
          blueden status           # Check current status
          blueden --help           # View all commands

        Or use client-specific commands:
          blueden-claude --help
          blueden-codex --help

        Documentation: https://app.bluebearsecurity.io/docs
      EOS
    else
      <<~EOS
        BlueDen has been installed!

        \e[33m⚠ Authentication may not have completed.\e[0m

        Installed clients:
#{client_list}

        To configure manually:
          1. Visit: https://app.bluebearsecurity.io/admin/api-keys
          2. Copy your API key
          3. Run: blueden configure --api-key YOUR_KEY

        Quick commands:
          blueden test             # Test the connection
          blueden status           # Check current status
          blueden --help           # View all commands

        Documentation: https://app.bluebearsecurity.io/docs
      EOS
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/blueden --version")
  end
end
