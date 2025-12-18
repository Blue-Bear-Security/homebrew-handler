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
    @config_dir = File.expand_path("~/.blueden")
    @client_name = meta[:client] || "claude"
    super
  end

  def _fetch(url:, resolved_url:, timeout:)
    FileUtils.mkdir_p(@config_dir)

    # Check for existing config with valid credentials
    @existing_config = load_existing_config
    if @existing_config && @existing_config["developer_api_key"] && @existing_config["api_endpoint"]
      ohai "Found existing BlueDen configuration"
      puts ""
      puts "  API Key: #{@existing_config["developer_api_key"][0..7]}..."
      puts "  Endpoint: #{@existing_config["api_endpoint"]}"
      puts ""
      puts "Existing credentials will be preserved."
      puts ""
    end

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

    # Skip API key creation if we already have valid credentials
    if @existing_config && @existing_config["developer_api_key"] && @existing_config["api_endpoint"]
      ohai "Preserving existing API key configuration"
    else
      setup_api_key(jwt_token)
    end

    # Save JWT token for install phase to download additional binaries
    # Store next to the downloaded file (in Homebrew cache) for install phase access
    jwt_buildpath_file = "#{temporary_path}.jwt"
    File.write(jwt_buildpath_file, jwt_token)
    File.chmod(0600, jwt_buildpath_file)
  end

  private

  def load_existing_config
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

    $stderr.puts ""
    $stderr.puts "  To authenticate, please:"
    $stderr.puts ""
    $stderr.puts "  1. Open this URL in your browser:"
    $stderr.puts "     \e[32m#{browser_url}\e[0m"
    $stderr.puts ""
    $stderr.puts "  2. Enter this code when prompted:"
    $stderr.puts ""
    $stderr.puts "     \e[1m\e[32m┌─────────────────┐\e[0m"
    $stderr.puts "     \e[1m\e[32m│    #{user_code}    │\e[0m"
    $stderr.puts "     \e[1m\e[32m└─────────────────┘\e[0m"
    $stderr.puts ""
    $stderr.puts "  Code expires in #{expires_in / 60} minutes"
    $stderr.puts ""
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
        # New key created - save it to ~/.blueden/config (single config location)
        config_file = File.join(@config_dir, "config")
        config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}
        config["api_endpoint"] = api_endpoint  # Use data ingestion URL from response
        config["developer_api_key"] = api_key
        config["monitor_poll_interval"] = config["monitor_poll_interval"] || 1.0
        config["configured_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        File.write(config_file, JSON.pretty_generate(config))
        File.chmod(0600, config_file)

        ohai "New API key created and saved (endpoint: #{api_endpoint})"
      else
        # Existing key found - the full key was only shown at creation time
        # User needs to get their existing key from the console or revoke and create a new one
        opoo "An existing API key was found for your account (#{key_prefix}...)"
        opoo "For security, the full key is only shown at creation time."
        opoo ""
        opoo "To configure, either:"
        opoo "  1. Get your key from: https://app.bluebearsecurity.io/admin/devices"
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
  version "0.4.8"

  # API base URL for downloads
  API_BASE = ENV.fetch("BLUEDEN_API_URL", "https://n93alh7z95.execute-api.us-east-1.amazonaws.com/prod")

  # Supported clients configuration
  CLIENTS = {
    "claude" => {
      name: "Claude Code",
      desc: "Anthropic Claude Code hooks",
      sha256: {
        "macos-arm64" => "4965d29ce603958681c038b5c4cec40731e9b7a395ea875b17a56f3e0ca3ef64",
        "macos-x86_64" => "24f06bdee3d28e42fc624ff706fc3d7bdb013c85ca04627cc0d1fa404899f995",
        "linux-arm64" => "5863a99444a4d92f1e8305b7e947ca21c23325f716e72789443c84894e23998f",
        "linux-x86_64" => "f28ac944b173e124f9dabf91219ff6bdf417006a03e089ea782aa6b5de32e652",
      }
    },
    "codex" => {
      name: "OpenAI Codex",
      desc: "OpenAI Codex CLI hooks",
      sha256: {
        "macos-arm64" => "6e7f195c73d1fc6ffa1fd8f177cbeb8f4141ea57692abb4feddda97930247132",
        "macos-x86_64" => "751162b5118b7e6f861e6aeb71f6f36abe8a0db4252a2a9212878bf753b4e705",
        "linux-arm64" => "890fc4a92ad0bd1b77e2073aba8905bb78c7c859b3e441033744cef770164d2e",
        "linux-x86_64" => "315b6ca7946ce6cbaa70d163b73e83a4f9b44c4b2749c3d8ad418d8d153a56a6",
      }
    },
    "copilot" => {
      name: "GitHub Copilot",
      desc: "GitHub Copilot CLI hooks",
      sha256: {
        "macos-arm64" => "390e8de46419f23936d7298b847435496fb1ba83b334b9972f075ce9e357b9a5",
        "macos-x86_64" => "bc9de68802e3b1ca9dc8555f2f6c7826b1a8ea3300a3d7b33263b966b5eca8bb",
        "linux-arm64" => "4a90af6d2cab252d14537319781c3bc32c75c8e8a7a2886042c2d12b6145f3c8",
        "linux-x86_64" => "a6bbc6cae0d20ffda5b4075d3c3218a0c27327cc692b274e5e4a35e953e25477",
      }
    },
    "cursor" => {
      name: "Cursor IDE",
      desc: "Cursor IDE hooks",
      sha256: {
        "macos-arm64" => "5f310b3606045cd42f0582f5867c5517aa6b7374d732dbf7f22d84d4c8ff2300",
        "macos-x86_64" => "9a700b875726f4fbd04d9566606d30240c551b641b57dbdf4876fc53df800c70",
        "linux-arm64" => "82871bc61e96f4d6189c060780fd1a4db000afbb785e2502f9798c87cd135f8e",
        "linux-x86_64" => "4d03c70963387167a8eae479d8fa5db6d9fb8e2be89fd5f11c1a317863884a61",
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

  url "#{API_BASE}/api/v1/bff/download/#{primary_client}-hooks/v0.4.8/#{platform_key}/blueden-#{primary_client}-hooks-#{platform_key}",
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

    # Read JWT token from cache file (saved during download phase in Homebrew cache)
    jwt_token = nil

    # Look for JWT file in buildpath or Homebrew cache
    possible_jwt_paths = [
      Dir["#{buildpath}/../*.jwt"].first,
      Dir["#{HOMEBREW_CACHE}/**/*.jwt"].first
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

    # Clean up all JWT and temporary files from Homebrew cache
    cleanup_homebrew_cache

    # Create main 'blueden' symlink to primary client
    bin.install_symlink "blueden-#{primary}" => "blueden"

    # Save installed clients to config at ~/.blueden/config
    config_dir = Pathname.new(File.expand_path("~/.blueden"))
    config_dir.mkpath
    config_file = config_dir / "config"

    config = config_file.exist? ? JSON.parse(config_file.read) : {}
    config["installed_clients"] = selected
    config["version"] = version.to_s
    config["platform"] = platform

    config_file.write(JSON.pretty_generate(config))
    config_file.chmod(0600)
  end

  private

  def cleanup_homebrew_cache
    # Clean up JWT files from buildpath (next to downloaded binaries)
    Dir["#{buildpath}/../*.jwt"].each { |f| FileUtils.rm_f(f) }

    # Clean up any .jwt files in Homebrew cache directory
    Dir["#{HOMEBREW_CACHE}/**/*.jwt"].each { |f| FileUtils.rm_f(f) }

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
    config_file = File.expand_path("~/.blueden/config")
    config_exists = File.exist?(config_file)

    client_list = selected.map { |c| "  - #{CLIENTS[c][:name]} (blueden-#{c})" }.join("\n")

    # Build setup instructions based on selected clients
    enable_instructions = []
    disable_instructions = []
    if selected.include?("claude")
      enable_instructions << "          blueden-claude enable"
      disable_instructions << "          blueden-claude disable"
    end
    if selected.include?("cursor")
      enable_instructions << "          blueden-cursor enable"
      disable_instructions << "          blueden-cursor disable"
    end
    if selected.include?("copilot")
      enable_instructions << "          blueden-copilot enable"
      disable_instructions << "          blueden-copilot disable"
    end
    if selected.include?("codex")
      enable_instructions << "          blueden-codex enable"
      disable_instructions << "          blueden-codex disable"
    end
    setup_section = enable_instructions.empty? ? "" : "\n        Enable each client:\n#{enable_instructions.join("\n")}\n\n        To disable:\n#{disable_instructions.join("\n")}\n"

    if config_exists
      <<~EOS
        BlueDen has been installed!

        \e[32m✓ Authentication complete!\e[0m

        Installed clients:
#{client_list}
#{setup_section}
        Your configuration is stored in: #{config_file}

        Quick commands:
          blueden test             # Test the connection
          blueden status           # Check current status
          blueden --help           # View all commands

        Documentation: https://app.bluebearsecurity.io/docs
      EOS
    else
      <<~EOS
        BlueDen has been installed!

        \e[33m⚠ Authentication may not have completed.\e[0m

        Installed clients:
#{client_list}

        To configure manually:
          1. Visit: https://app.bluebearsecurity.io/admin/devices
          2. Copy your API key
          3. Run: blueden configure --api-key YOUR_KEY
#{setup_section}
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