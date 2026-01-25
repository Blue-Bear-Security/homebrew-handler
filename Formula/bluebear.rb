# Homebrew Formula for BlueBear CLI - AI Coding Agent Governance
# DEN-750: Single unified Go binary for macOS and Linux
#
# Installation:
#   brew tap Blue-Bear-Security/handler
#   brew install bluebear

require "json"
require "open3"

# DEN-577: Environment configuration for multi-environment support
BLUEBEAR_ENVIRONMENT = ""
BLUEBEAR_ENV_SUFFIX = BLUEBEAR_ENVIRONMENT.empty? ? "" : "-#{BLUEBEAR_ENVIRONMENT}"
BINARY_PREFIX = "bluebear"

# Custom download strategy for authenticated downloads
class BluebearOAuthDownloadStrategy < CurlDownloadStrategy
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

    # Try to open browser (macOS or Linux)
    browser_opened = false
    if OS.mac?
      system "open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    elsif which("xdg-open")
      system "xdg-open", browser_url, [:out, :err] => "/dev/null"
      browser_opened = true
    end

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

class Bluebear < Formula
  desc "BlueBear - Secure AI coding agent governance for Claude, Codex, Copilot, and more"
  homepage "https://bluebearsecurity.io"
  version "0.5.1"

  API_BASE = ENV.fetch("BLUEDEN_API_URL", "https://api.bluebearsecurity.io")

  # Platform-specific configuration (macOS and Linux)
  if OS.mac?
    if Hardware::CPU.arm?
      sha256 "d71b8dafcad5cc18ee28ab6b6f311e895c3e4e78ecef9ebb8d18033dd930aec1"
      platform_suffix = "macos-arm64"
    else
      sha256 "f251b352b7002e5be203206d991f17e5ffeacdb6dd20fea9a79619f0ba2b2691"
      platform_suffix = "macos-x86_64"
    end
  else
    if Hardware::CPU.arm?
      sha256 "9cc799191fa733f9921ec636d3dca4a6853a5a0c13ed8c9e45f7a3f8d1621626"
      platform_suffix = "linux-arm64"
    else
      sha256 "8e626292ef1d95f51ede72fe31d5cdcbda5e56d87713ee2e5b48fb7e2ec2901c"
      platform_suffix = "linux-x86_64"
    end
  end

  # DEN-750: Single unified binary (Go build)
  url "#{API_BASE}/api/v1/bff/download/bluebear/v0.5.1/#{platform_suffix}/bluebear-#{platform_suffix}.tar.gz",
    using: BluebearOAuthDownloadStrategy

  def install
    platform = OS.mac? ? (Hardware::CPU.arm? ? "macos-arm64" : "macos-x86_64") : (Hardware::CPU.arm? ? "linux-arm64" : "linux-x86_64")

    ohai "Installing BlueBear v#{version} for #{platform}"

    # Find the extracted binary
    binary_path = Dir["bluebear-*"].find { |f| File.file?(f) && !f.end_with?('.tar.gz') }

    if binary_path
      # Make executable and install
      chmod 0755, binary_path
      bin.install binary_path => BINARY_PREFIX
      ohai "✓ Installed #{BINARY_PREFIX}"

      # Generate and install shell completions
      ohai "Installing shell completions..."
      generate_completions
    else
      opoo "Could not find bluebear binary"
      ohai "Contents of buildpath:"
      Dir["*"].each { |f| puts "  #{f}" }
    end
  end

  def generate_completions
    # Generate shell completions using the installed binary
    # Note: Cobra generates completions for "bluebear" but we may install as a different name
    # (e.g., bluebear-pr-478 for PR environments), so we replace the command name in the output
    output = Utils.safe_popen_read(bin/BINARY_PREFIX, "completion", "bash")
    output = output.gsub("bluebear", BINARY_PREFIX)
    (bash_completion/BINARY_PREFIX).write output

    output = Utils.safe_popen_read(bin/BINARY_PREFIX, "completion", "zsh")
    output = output.gsub("bluebear", BINARY_PREFIX)
    (zsh_completion/"_#{BINARY_PREFIX}").write output

    output = Utils.safe_popen_read(bin/BINARY_PREFIX, "completion", "fish")
    output = output.gsub("bluebear", BINARY_PREFIX)
    (fish_completion/"#{BINARY_PREFIX}.fish").write output
  rescue => e
    opoo "Could not generate shell completions: #{e.message}"
  end

  def post_install
    # Save installation metadata to config
    # Note: This runs outside Homebrew's sandbox, so we can write to home directory
    platform = OS.mac? ? (Hardware::CPU.arm? ? "macos-arm64" : "macos-x86_64") : (Hardware::CPU.arm? ? "linux-arm64" : "linux-x86_64")

    require 'etc'
    real_home = Etc.getpwuid.dir
    config_dir = "#{real_home}/.bluebear#{BLUEBEAR_ENV_SUFFIX}"
    FileUtils.mkdir_p(config_dir)
    config_path = "#{config_dir}/config"

    begin
      # Remove Apple extended attributes that may block writes
      # (com.apple.provenance set during sandboxed download)
      if OS.mac? && File.exist?(config_path)
        system_command "xattr", args: ["-c", config_path], print_stderr: false
      end

      config = File.exist?(config_path) ? JSON.parse(File.read(config_path)) : {}
      config["version"] = version.to_s
      config["platform"] = platform
      config["install_type"] = "formula"
      config["installed_at"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      File.write(config_path, JSON.pretty_generate(config))
      File.chmod(0600, config_path)
    rescue => e
      # Config metadata is non-critical, continue with install
      opoo "Could not update config metadata: #{e.message}"
    end

    # Run bluebear enable to set up all handlers
    ohai "Running #{BINARY_PREFIX} enable..."
    system bin/BINARY_PREFIX, "enable"
  end

  def caveats
    config_file = File.expand_path("~/.bluebear#{BLUEBEAR_ENV_SUFFIX}/config")
    config_exists = File.exist?(config_file)

    if config_exists
      <<~EOS
        BlueBear has been installed and configured!

        Configuration: #{config_file}
        Documentation: https://app.bluebearsecurity.io/docs

        Before uninstalling, run: #{BINARY_PREFIX} disable
      EOS
    else
      <<~EOS
        BlueBear has been installed!

        \e[33m⚠ Authentication may not have completed.\e[0m

        To configure manually:
          1. Visit: https://app.bluebearsecurity.io/admin/devices
          2. Copy your API key
          3. Run: #{BINARY_PREFIX} configure --api-key YOUR_KEY

        Documentation: https://app.bluebearsecurity.io/docs

        Before uninstalling, run: #{BINARY_PREFIX} disable
      EOS
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/#{BINARY_PREFIX} version")
  end
end
