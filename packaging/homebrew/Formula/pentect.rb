class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.96"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.96/pentect-macos-aarch64"
      sha256 "8aac201429c97515ffe58aa5efb486d303c640d169b6c3e597fcb7814d08ea4c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.96/pentect-macos-x86_64"
      sha256 "761089445c20ee9668fa4307a728ed7c0104c2eb225f6bd2571b511cffa38a6d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.96/pentect-linux-aarch64"
      sha256 "77d21128cf4a9b44cefc72bcfbf86d0458186b76ca7a9bc0f9c086e486b1ef98"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.96/pentect-linux-x86_64"
      sha256 "e685e9e5749caa6912ca78dade4744911acc8f0dfb1877c1372651a73bfa3d6d"
    end
  end

  def install
    binary = Dir["pentect-*"].first
    bin.install binary => "pentect"
    (bin/".pentect-managed-install.json").write <<~JSON
      {"version":1,"manager":"homebrew","update":"brew upgrade EdamAme-x/pentect/pentect","uninstall":"brew uninstall EdamAme-x/pentect/pentect"}
    JSON
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pentect version")
  end
end
