# Homebrew Cask for BlueBear CLI - AI Coding Agent Governance
# DEN-750: Single unified Go binary with proper uninstall hooks
#
# Casks provide uninstall stanzas that formulas lack, enabling proper cleanup
# when running `brew uninstall --cask bluebear`.
#
# Installation:
#   brew tap Blue-Bear-Security/client-releases-artifacts
#   brew install --cask bluebear
#
# Usage:
#   bluebear status              # Check daemon status
#   bluebear claude enable       # Enable Claude Code hooks
#   bluebear cursor enable       # Enable Cursor hooks

require "json"
require "open3"

# DEN-577: Environment configuration for multi-environment support
# These constants are replaced by generate-formulas.sh during build
BLUEBEAR_ENVIRONMENT = ""
BLUEBEAR_ENV_SUFFIX = BLUEBEAR_ENVIRONMENT.empty? ? "" : "-#{BLUEBEAR_ENVIRONMENT}"
BINARY_PREFIX = "bluebear"

# Custom download strategy for authenticated downloads with OAuth device flow
class BluebearCaskDownloadStrategy < CurlDownloadStrategy
  def initialize(url, name, version, **meta)
    @api_base = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")
    @console_url = ENV.fetch("BLUEDEN_CONSOLE_URL", "https://app.bluebearsecurity.io")
    @config_dir = File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}")
    super
  end

  def _fetch(url:, resolved_url:, timeout:)
    FileUtils.mkdir_p(@config_dir)

    auth_token = nil
    auth_type = nil

    # Check for existing API key (upgrades)
    @existing_config = load_existing_config
    if @existing_config && @existing_config["developer_api_key"] && !@existing_config["developer_api_key"].empty?
      auth_token = @existing_config["developer_api_key"]
      auth_type = 'api_key'
      ohai "Using existing API key for download (upgrade mode)"
    end

    # If no existing API key, run OAuth device flow
    unless auth_token
      ohai "BlueBear OAuth Authentication Required"
      puts ""

      auth_token = authenticate_device_flow
      auth_type = 'jwt'

      unless auth_token
        raise CurlDownloadStrategyError, <<~EOS
          BlueBear authentication failed or timed out.

          Please try again, or manually configure:
            1. Visit: #{@console_url}/settings
            2. Copy your API key
            3. After install, run: #{BINARY_PREFIX} configure --api-key YOUR_KEY
        EOS
      end
    end

    ohai "Downloading BlueBear binary..."
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

    if auth_type == 'jwt'
      setup_api_key(auth_token)
    else
      ohai "Preserving existing API key configuration"
    end
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

    # Open browser on macOS
    system "open", browser_url, [:out, :err] => "/dev/null"

    $stderr.puts ""
    $stderr.puts "  Authenticating... browser opened automatically."
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

    hostname = `hostname`.strip rescue "unknown"
    platform = "macOS"
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
      opoo "Could not set up API key automatically. Configure later with: #{BINARY_PREFIX} configure"
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
        config_file = File.join(@config_dir, "config")
        config = File.exist?(config_file) ? JSON.parse(File.read(config_file)) : {}
        config["api_endpoint"] = api_endpoint
        config["bff_endpoint"] = @api_base
        config["developer_api_key"] = api_key
        config["configured_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        File.write(config_file, JSON.pretty_generate(config))
        File.chmod(0600, config_file)

        ohai "New API key created and saved"
      else
        key_prefix = data["key_prefix"]
        opoo "An existing API key was found for your account (#{key_prefix}...)"
      end
    else
      error_msg = response["error"] || response["message"] || "Unknown error"
      opoo "API key creation failed: #{error_msg}"
    end
  end
end

cask "bluebear" do
  version "0.5.0"
  sha256 "db0b95fcfc99d7da5998da001477e16acfe65624febb45061877a209b1e0add0"

  url "https://api.bluebearsecurity.io/api/v1/bff/download/bluebear/v0.5.0/macos-arm64/bluebear-macos-arm64.tar.gz",
      using: BluebearCaskDownloadStrategy
  name "BlueBear"
  desc "Secure AI coding agent governance for Claude, Codex, Copilot, and more"
  homepage "https://bluebearsecurity.io"

  # Link the binary
  binary "bluebear-macos-arm64", target: "#{BINARY_PREFIX}"

  # Run bluebear enable after installation
  postflight do
    # Remove quarantine attribute to prevent Gatekeeper blocking
    system_command "xattr", args: ["-cr", staged_path.to_s], print_stderr: false

    # Check if config has API endpoint (may be missing if download was cached)
    require 'etc'
    real_home = Etc.getpwuid.dir
    config_dir = "#{real_home}/.bluebear#{BLUEBEAR_ENV_SUFFIX}"
    config_path = "#{config_dir}/config"

    config_valid = false
    begin
      if File.exist?(config_path)
        config = JSON.parse(File.read(config_path))
        config_valid = config["api_endpoint"] && !config["api_endpoint"].empty? &&
                       config["developer_api_key"] && !config["developer_api_key"].empty?
      end
    rescue
      config_valid = false
    end

    unless config_valid
      # Delete cached download to force fresh OAuth on next install
      cache_dir = "#{real_home}/Library/Caches/Homebrew/downloads"
      Dir.glob("#{cache_dir}/*bluebear*").each { |f| FileUtils.rm_f(f) }

      raise CaskError, <<~EOS
        Authentication required but download was cached.

        The cached download has been cleared. Please reinstall:
          brew reinstall --cask bluebear
      EOS
    end

    # Save installation metadata to config
    FileUtils.mkdir_p(config_dir)

    begin
      # Remove Apple extended attributes that may block writes
      system_command "xattr", args: ["-c", config_path], print_stderr: false if File.exist?(config_path)

      config = File.exist?(config_path) ? JSON.parse(File.read(config_path)) : {}
      config["version"] = version.to_s
      config["platform"] = "macos-arm64"
      config["install_type"] = "cask"
      config["installed_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      File.write(config_path, JSON.pretty_generate(config))
      File.chmod(0600, config_path)
    rescue => e
      opoo "Could not update config metadata: #{e.message}"
    end

    # Generate and install shell completions
    # Note: Cobra generates completions for "bluebear" but we may install as a different name
    # (e.g., bluebear-pr-478 for PR environments), so we replace the command name in the output
    ohai "Installing shell completions..."
    begin
      zsh_completions_dir = "#{HOMEBREW_PREFIX}/share/zsh/site-functions"
      bash_completions_dir = "#{HOMEBREW_PREFIX}/etc/bash_completion.d"
      fish_completions_dir = "#{HOMEBREW_PREFIX}/share/fish/vendor_completions.d"

      FileUtils.mkdir_p(zsh_completions_dir)
      FileUtils.mkdir_p(bash_completions_dir)
      FileUtils.mkdir_p(fish_completions_dir)

      # Generate zsh completion and replace command name
      zsh_output, zsh_status = Open3.capture2("#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", "completion", "zsh")
      if zsh_status.success?
        # Replace 'bluebear' with actual binary name for PR environments
        zsh_output = zsh_output.gsub("bluebear", BINARY_PREFIX)
        File.write("#{zsh_completions_dir}/_#{BINARY_PREFIX}", zsh_output)
        ohai "Installed zsh completion"
      end

      # Generate bash completion and replace command name
      bash_output, bash_status = Open3.capture2("#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", "completion", "bash")
      if bash_status.success?
        bash_output = bash_output.gsub("bluebear", BINARY_PREFIX)
        File.write("#{bash_completions_dir}/#{BINARY_PREFIX}", bash_output)
        ohai "Installed bash completion"
      end

      # Generate fish completion and replace command name
      fish_output, fish_status = Open3.capture2("#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", "completion", "fish")
      if fish_status.success?
        fish_output = fish_output.gsub("bluebear", BINARY_PREFIX)
        File.write("#{fish_completions_dir}/#{BINARY_PREFIX}.fish", fish_output)
        ohai "Installed fish completion"
      end
    rescue => e
      opoo "Could not install shell completions: #{e.message}"
    end

    # Run bluebear enable to set up daemon
    ohai "Running #{BINARY_PREFIX} enable..."
    system_command "#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", args: ["enable"]

    # Ask user if they want to ingest existing history
    puts ""
    print "Would you like to ingest existing Claude and Cursor history? [Y/n] "
    $stdout.flush
    response = $stdin.gets&.strip&.downcase || "y"

    if response.empty? || response == "y" || response == "yes"
      ohai "Starting history ingestion in background..."

      # Run ingest-history in background for both clients
      # Go binary handles its own logging
      pid = spawn(
        "#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", "ingest-history", "claude",
        [:out, :err] => "/dev/null"
      )
      Process.detach(pid)

      pid = spawn(
        "#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", "ingest-history", "cursor",
        [:out, :err] => "/dev/null"
      )
      Process.detach(pid)

      puts "  History ingestion running in background."
    else
      puts "  Skipped. You can run later with: '#{BINARY_PREFIX} ingest-history claude' or '#{BINARY_PREFIX} ingest-history cursor'"
    end
  end

  # Run bluebear disable before removal - THIS IS WHY WE USE CASK!
  uninstall_preflight do
    ohai "Running #{BINARY_PREFIX} disable..."
    system_command "#{HOMEBREW_PREFIX}/bin/#{BINARY_PREFIX}", args: ["disable"]

    # Remove shell completions
    ohai "Removing shell completions..."
    begin
      zsh_completion = "#{HOMEBREW_PREFIX}/share/zsh/site-functions/_#{BINARY_PREFIX}"
      bash_completion = "#{HOMEBREW_PREFIX}/etc/bash_completion.d/#{BINARY_PREFIX}"
      fish_completion = "#{HOMEBREW_PREFIX}/share/fish/vendor_completions.d/#{BINARY_PREFIX}.fish"

      FileUtils.rm_f(zsh_completion) if File.exist?(zsh_completion)
      FileUtils.rm_f(bash_completion) if File.exist?(bash_completion)
      FileUtils.rm_f(fish_completion) if File.exist?(fish_completion)
    rescue => e
      opoo "Could not remove shell completions: #{e.message}"
    end

    # PR environments: always clean up config (ephemeral, for testing)
    # Production: keep config for seamless upgrades - use 'brew uninstall --zap' for full cleanup
    unless BLUEBEAR_ENVIRONMENT.empty?
      require 'etc'
      real_home = Etc.getpwuid.dir
      config_dir = "#{real_home}/.bluebear#{BLUEBEAR_ENV_SUFFIX}"
      if Dir.exist?(config_dir)
        ohai "Removing PR environment config: #{config_dir}"
        FileUtils.rm_rf(config_dir)
      end
    end
  end

  # Clean up config on zap (brew uninstall --zap) - fallback if uninstall_preflight missed it
  zap trash: [
    "~/.bluebear#{BLUEBEAR_ENV_SUFFIX}",
    "#{HOMEBREW_PREFIX}/share/zsh/site-functions/_#{BINARY_PREFIX}",
    "#{HOMEBREW_PREFIX}/etc/bash_completion.d/#{BINARY_PREFIX}",
    "#{HOMEBREW_PREFIX}/share/fish/vendor_completions.d/#{BINARY_PREFIX}.fish",
  ]
end
