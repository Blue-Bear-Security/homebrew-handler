# Homebrew Cask for BlueBear CLI - AI Coding Agent Governance
# DEN-352: Using cask instead of formula to avoid dylib relocation errors
#
# Casks don't run install_name_tool on binaries, which is perfect for
# PyInstaller bundles that have pre-compiled wheels with minimal header padding.
#
# Installation:
#   brew tap Blue-Bear-Security/bluebear
#   brew install --cask bluebear
#
# Usage:
#   bluebear claude enable       # Enable Claude Code hooks
#   bluebear codex enable        # Enable Codex hooks
#   bluebear copilot enable      # Enable Copilot hooks
#   bluebear cursor enable       # Enable Cursor hooks

require "json"
require "open3"

# Custom download strategy that handles OAuth device flow authentication
class BluebearOAuthDownloadStrategy < CurlDownloadStrategy
  def initialize(url, name, version, **meta)
    @api_base = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")
    @console_url = ENV.fetch("BLUEDEN_CONSOLE_URL", "https://app.bluebearsecurity.io")
    @config_dir = File.expand_path("~/.bluebear")
    super
  end

  def _fetch(url:, resolved_url:, timeout:)
    FileUtils.mkdir_p(@config_dir)

    # Check for existing config with valid credentials
    @existing_config = load_existing_config
    @has_existing_key = @existing_config && @existing_config["developer_api_key"] && @existing_config["api_endpoint"]

    if @has_existing_key
      ohai "Found existing BlueBear configuration"
      puts ""
      puts "  API Key: #{@existing_config["developer_api_key"][0..7]}..."
      puts "  Endpoint: #{@existing_config["api_endpoint"]}"
      puts ""
      puts "Existing credentials will be preserved."
      puts ""
    end

    ohai "BlueBear Authentication"
    puts ""
    puts "Quick authentication required for download..."
    puts ""

    jwt_token = authenticate_device_flow

    unless jwt_token
      raise CurlDownloadStrategyError, <<~EOS
        BlueBear authentication failed or timed out.

        Please try again, or manually configure:
          1. Visit: #{@console_url}/settings
          2. Copy your API key
          3. After install, run: bluebear <client> configure --api-key YOUR_KEY
      EOS
    end

    ohai "Downloading BlueBear binaries..."
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
    if @has_existing_key
      ohai "Preserving existing API key configuration"
    else
      setup_api_key(jwt_token)
    end

    # Save JWT token for downloading additional binaries in preflight
    jwt_file = File.join(@config_dir, "install.jwt")
    File.write(jwt_file, jwt_token)
    File.chmod(0600, jwt_file)

    # Parent class (CurlDownloadStrategy) handles moving temporary_path to cached_location
    ohai "Download complete"
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

    $stderr.puts ""
    if browser_opened
      $stderr.puts "  Authenticating... browser opened automatically."
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
      when "authorization_pending", "slow_down"
        poll_interval += 1 if error == "slow_down"
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

    hostname = `hostname`.strip rescue "unknown"
    platform = OS.mac? ? "macOS" : "Linux"
    arch = Hardware::CPU.arm? ? "ARM64" : "x86_64"

    request_body = {
      cli_token: jwt_token,
      device_name: "#{hostname} (#{platform} #{arch})",
      device_hostname: hostname,
      device_platform: platform,
      device_arch: arch,
      force_new: true
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
      api_key = data["api_key"]
      api_endpoint = data["api_endpoint"] || @api_base

      if api_key
        # Save API key to config file temporarily during download phase.
        # It will be moved to keychain with proper ACLs in preflight phase
        # after binaries are extracted and we know their paths. (DEN-516)
        config_file = File.join(@config_dir, "config")
        config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}
        config["api_endpoint"] = api_endpoint
        config["bff_endpoint"] = @api_base  # BFF API URL for version checks
        config["developer_api_key"] = api_key
        config["monitor_poll_interval"] = 1.0
        config["configured_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        File.write(config_file, JSON.pretty_generate(config))
        File.chmod(0600, config_file)

        ohai "New API key created and saved"
      else
        key_prefix = data["key_prefix"]
        opoo "An existing API key was found for your account (#{key_prefix}...)"
        opoo "For security, the full key is only shown at creation time."
        opoo "To configure, get your key from: https://app.bluebearsecurity.io/admin/devices"
      end
    else
      error_msg = response["error"] || response["message"] || "Unknown error"
      opoo "API key creation failed: #{error_msg}"
      opoo "Configure later with: bluebear <client> configure"
    end
  end

end

cask "bluebear" do
  version "0.4.25"

  # Platform-specific configuration
  if Hardware::CPU.arm?
    sha256 "7ce9b1e9de12c769d003941000335940707a76a073af46c42f34732ab4a797d8"
    platform_suffix = "macos-arm64"
  else
    sha256 "9758c3577cb018cc81a3699d2f9b75fe865e774ec4fbbc66b8b6a7ce535bc3b1"
    platform_suffix = "macos-x86_64"
  end

  api_base = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")

  url "#{api_base}/api/v1/bff/download/claude-hooks/v#{version}/#{platform_suffix}/bluebear-claude-hooks-#{platform_suffix}.tar.gz",
      using: BluebearOAuthDownloadStrategy

  name "BlueBear"
  desc "Secure AI coding agent governance for Claude, Codex, Copilot, and more"
  homepage "https://bluebearsecurity.io"

  # Install all client binaries - use preflight so bin/ exists before binary stanzas run
  preflight do
    begin
      # Write to a file to prove preflight runs (stdout might be suppressed)
      debug_log = File.expand_path("~/.bluebear/preflight_debug.log")
      FileUtils.mkdir_p(File.dirname(debug_log))
      File.open(debug_log, "w") do |f|
        f.puts "Preflight started at #{Time.now}"
        f.puts "staged_path = #{staged_path}"
        f.puts "Contents of staged_path:"
        Dir["#{staged_path}/*"].each { |entry| f.puts "  #{entry}" }
        f.puts "Deep contents (first 30):"
        Dir["#{staged_path}/**/*"].first(30).each { |entry| f.puts "  #{entry}" }
      end

      puts "==> BlueBear preflight starting (log at #{debug_log})..."

      # Create bin directory unconditionally
      bin_dir = "#{staged_path}/bin"
      FileUtils.mkdir_p(bin_dir)

      # Client SHA256 hashes
      client_hashes = {
        "claude" => {
          sha256_arm64: "7ce9b1e9de12c769d003941000335940707a76a073af46c42f34732ab4a797d8",
          sha256_x86_64: "9758c3577cb018cc81a3699d2f9b75fe865e774ec4fbbc66b8b6a7ce535bc3b1",
        },
        "codex" => {
          sha256_arm64: "b4c307a37532a4e2889869df008b68cb54531fd4a51b97891ef4858db4771d0f",
          sha256_x86_64: "be2d103172636bb64d1c4af9f15a81c7716c277ed8592bdf8d1ffd5d50af2fbc",
        },
        "copilot" => {
          sha256_arm64: "18c11d2ccc56a3dc28ac20a4fd61907cd917da15bcbfd906a0bbc203b3174117",
          sha256_x86_64: "4cf42a922e34017cfff265f21c206fffa7eacca3dbf292528651d15f2eebff33",
        },
        "cursor" => {
          sha256_arm64: "744abe4c72f1a484db1be0a67af0ad21ed67489c43f68fe9c0532778d380d86c",
          sha256_x86_64: "27621aba82df443ade6f58c7a0f80d600cf8c1b08e2751647c4b69b9c3bcaa01",
        },
      }

      platform_suffix = Hardware::CPU.arm? ? "macos-arm64" : "macos-x86_64"
      api_base = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")

      # Get JWT token saved during download (in ~/.bluebear/install.jwt)
      jwt_file = File.expand_path("~/.bluebear/install.jwt")
      jwt_token = File.exist?(jwt_file) ? File.read(jwt_file).strip : nil

      File.open(debug_log, "a") do |f|
        f.puts "JWT file path: #{jwt_file}"
        f.puts "JWT file exists: #{File.exist?(jwt_file)}"
        f.puts "JWT token present: #{jwt_token ? 'yes' : 'no'}"
      end

      # The primary client (claude) is already downloaded and extracted
      # Find the extracted directory - try multiple patterns
      claude_dir = Dir["#{staged_path}/bluebear-claude-hooks-*"].first
      puts "==> Looking for claude: pattern match = #{claude_dir || 'nil'}"

      if claude_dir && File.directory?(claude_dir)
        puts "==> Found claude dir, renaming to bluebear-claude"
        FileUtils.mv(claude_dir, "#{staged_path}/bluebear-claude")
      elsif File.directory?("#{staged_path}/bluebear-hooks")
        puts "==> Found bluebear-hooks directly"
        FileUtils.mkdir_p("#{staged_path}/bluebear-claude")
        FileUtils.mv("#{staged_path}/bluebear-hooks", "#{staged_path}/bluebear-claude/bluebear-hooks")
        FileUtils.mv("#{staged_path}/_internal", "#{staged_path}/bluebear-claude/_internal") if File.directory?("#{staged_path}/_internal")
      else
        puts "==> WARNING: Could not find claude binary!"
      end

    # Make claude binary executable and remove quarantine attribute
    claude_binary = "#{staged_path}/bluebear-claude/bluebear-hooks"
    if File.exist?(claude_binary)
      FileUtils.chmod(0755, claude_binary)
      # Remove macOS quarantine attribute to prevent Gatekeeper blocking
      system("xattr", "-cr", "#{staged_path}/bluebear-claude")
    end

    # Download additional clients
    ["codex", "copilot", "cursor"].each do |client|
      next unless jwt_token

      ohai "Downloading #{client} binary..."

      tarball_url = "#{api_base}/api/v1/bff/download/#{client}-hooks/v#{version}/#{platform_suffix}/bluebear-#{client}-hooks-#{platform_suffix}.tar.gz"
      tarball_path = "#{staged_path}/bluebear-#{client}.tar.gz"

      # Download with JWT auth (use system() since system_command! not allowed in preflight)
      curl_result = system("curl", "-fsSL", "-H", "Authorization: Bearer #{jwt_token}", "-o", tarball_path, tarball_url)

      if curl_result && File.exist?(tarball_path) && File.size(tarball_path) > 1000
        # Verify SHA256
        sha_key = Hardware::CPU.arm? ? :sha256_arm64 : :sha256_x86_64
        expected_sha = client_hashes[client][sha_key]
        actual_sha = Digest::SHA256.file(tarball_path).hexdigest

        if actual_sha == expected_sha
          # Extract tarball (use system() since system_command! not allowed in preflight)
          system("tar", "-xzf", tarball_path, "-C", staged_path.to_s)

          # Rename extracted directory
          client_dir = Dir["#{staged_path}/bluebear-#{client}-hooks-*"].first
          if client_dir && File.directory?(client_dir)
            FileUtils.mv(client_dir, "#{staged_path}/bluebear-#{client}")
          elsif File.exist?("#{staged_path}/bluebear-hooks")
            FileUtils.mkdir_p("#{staged_path}/bluebear-#{client}")
            FileUtils.mv("#{staged_path}/bluebear-hooks", "#{staged_path}/bluebear-#{client}/bluebear-hooks")
            FileUtils.mv("#{staged_path}/_internal", "#{staged_path}/bluebear-#{client}/_internal") if File.directory?("#{staged_path}/_internal")
          end

          # Make binary executable and remove quarantine
          binary_path = "#{staged_path}/bluebear-#{client}/bluebear-hooks"
          if File.exist?(binary_path)
            FileUtils.chmod(0755, binary_path)
            system("xattr", "-cr", "#{staged_path}/bluebear-#{client}")
          end

          ohai "✓ Downloaded #{client}"
        else
          opoo "SHA256 mismatch for #{client}, skipping"
        end

        FileUtils.rm_f(tarball_path)
      else
        opoo "Failed to download #{client}"
      end
    end

    # Clean up JWT file
    FileUtils.rm_f(jwt_file) if jwt_file

    # Create wrapper scripts for each client
    bin_dir = "#{staged_path}/bin"
    FileUtils.mkdir_p(bin_dir)

    ohai "Creating wrapper scripts in #{bin_dir}..."
    created_wrappers = []

    ["claude", "codex", "copilot", "cursor"].each do |client|
      binary_path = "#{staged_path}/bluebear-#{client}/bluebear-hooks"
      if File.exist?(binary_path)
        wrapper_path = "#{bin_dir}/bluebear-#{client}"
        File.write(wrapper_path, <<~BASH)
          #!/bin/bash
          exec "#{binary_path}" "$@"
        BASH
        FileUtils.chmod(0755, wrapper_path)
        created_wrappers << client
      end
    end

    if created_wrappers.empty?
      opoo "No client binaries were found! Wrapper scripts not created."
      opoo "Final staged_path contents: #{Dir["#{staged_path}/**/*"].first(20).join(', ')}"
    end

    # Create unified 'bluebear' wrapper
    File.write("#{bin_dir}/bluebear", <<~BASH)
      #!/bin/bash
      # BlueBear unified CLI wrapper
      # Usage: bluebear <client> <command> [options]

      set -e

      show_help() {
          echo "BlueBear - Unified CLI for AI Agent Governance"
          echo ""
          echo "Usage: bluebear <client> <command> [options]"
          echo ""
          echo "Supported clients:"
          echo "  claude    Claude Code / Anthropic"
          echo "  codex     OpenAI Codex CLI"
          echo "  copilot   GitHub Copilot"
          echo "  cursor    Cursor IDE"
          echo ""
          echo "Commands vary by client. Common commands include:"
          echo "  enable        Enable hooks for the client"
          echo "  disable       Disable hooks for the client"
          echo "  configure     Configure API credentials"
          echo "  status        Show integration status"
          echo ""
          echo "Examples:"
          echo "  bluebear claude enable         Enable Claude Code hooks"
          echo "  bluebear claude disable        Disable Claude Code hooks"
          echo "  bluebear codex enable          Enable Codex hooks"
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
          echo "bluebear version #{version}"
      }

      case "${1:-}" in
          -h|--help) show_help; exit 0 ;;
          -v|--version) show_version; exit 0 ;;
          "") show_help; exit 0 ;;
      esac

      client="$1"
      shift

      case "$client" in
          claude|codex|copilot|cursor)
              binary="#{staged_path}/bluebear-$client/bluebear-hooks"
              if [[ ! -x "$binary" ]]; then
                  echo "Error: Client '$client' is not installed." >&2
                  exit 1
              fi
              if [[ $# -eq 0 ]]; then
                  exec "$binary" --help
              fi
              exec "$binary" "$@"
              ;;
          *)
              echo "Error: Unknown client: $client" >&2
              echo "Supported clients: claude, codex, copilot, cursor" >&2
              exit 1
              ;;
      esac
    BASH
    FileUtils.chmod(0755, "#{bin_dir}/bluebear")

    # Save API key to config file (DEN-516: keychain disabled due to compatibility issues)
    # The API key stays in ~/.bluebear/config with 0600 permissions.
    # Future: re-enable keychain once code signing is implemented for PyInstaller bundles.
    config_dir = File.expand_path("~/.bluebear")
    FileUtils.mkdir_p(config_dir)
    config_file = "#{config_dir}/config"

    config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}

    # Save installed clients to config
    config["installed_clients"] = ["claude", "codex", "copilot", "cursor"]
    config["version"] = version.to_s
    config["platform"] = platform_suffix
    config["install_type"] = "cask"

    File.write(config_file, JSON.pretty_generate(config))
    FileUtils.chmod(0600, config_file)

    # Print success message at the end of preflight
    puts ""
    puts "==> BlueBear installation complete!"
    puts ""
    puts "Clients are installed but \e[32mnot yet enabled\e[0m."
    puts ""
    puts "\e[32mEnable each client:\e[0m"
    puts "  bluebear claude enable"
    puts "  bluebear codex enable"
    puts "  bluebear copilot enable"
    puts "  bluebear cursor enable"
    puts ""
    puts "To disable:"
    puts "  bluebear claude disable"
    puts "  bluebear codex disable"
    puts "  bluebear copilot disable"
    puts "  bluebear cursor disable"
    puts ""
    puts "Your configuration is stored in: ~/.bluebear/config"
    puts ""
    puts "Documentation: https://app.bluebearsecurity.io/docs"
    puts ""

    rescue => e
      puts "==> ERROR in preflight: #{e.class}: #{e.message}"
      puts e.backtrace.first(5).join("\n")
      raise
    end
  end

  # Symlink wrapper scripts to Homebrew bin
  # All clients are downloaded in preflight - if any fail, wrapper won't exist
  binary "bin/bluebear"
  binary "bin/bluebear-claude"
  binary "bin/bluebear-codex"
  binary "bin/bluebear-copilot"
  binary "bin/bluebear-cursor"

  # Uninstall preflight: disable any running clients before Homebrew removes binaries.
  uninstall_preflight do
    clients = %w[claude codex copilot cursor]
    errors = []

    bluebear_bin = HOMEBREW_PREFIX/"bin/bluebear"
    if bluebear_bin.exist?
      clients.each do |client|
        # Run the client disable command to stop daemons and clean hooks.
        puts "==> Disabling #{client}..."
        begin
          result = system_command bluebear_bin, args: [client, "disable"], print_stderr: false
          if result.success?
            puts "==> Disabled #{client}"
          else
            errors << "#{client}: exit #{result.exit_status}"
          end
        rescue => e
          errors << "#{client}: #{e.class}: #{e.message}"
        end
      end
    else
      puts "==> Warning: bluebear binary not found; skipping client disable."
    end

    if errors.any?
      puts "==> Warning: one or more clients failed to disable:"
      errors.each { |error| puts "  - #{error}" }
    end

    # Note: API key is stored in ~/.bluebear/config (not keychain)
    # We intentionally do NOT delete the config file on uninstall to preserve
    # user credentials for reinstall. Users can manually delete if needed.
  end

  # Homebrew automatically:
  # 1. Removes binary symlinks from /opt/homebrew/bin/
  # 2. Deletes the entire staged_path directory in Caskroom
end
