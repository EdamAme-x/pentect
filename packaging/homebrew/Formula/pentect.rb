class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.87"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.87/pentect-macos-aarch64"
      sha256 "93e03900fcd0b9549bb4c89901bbbd57b526408d97ee97a80a4274e55583ec3e"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.87/pentect-macos-x86_64"
      sha256 "a427ed52baab55875095378c1ff2cc5b6184e1fd8c3ee9b78dac6443afaa130b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.87/pentect-linux-aarch64"
      sha256 "b7ae755006cfeb8a2cdc1d586b8b5177aec3d2fbf4b66bfa935dff47e62913c6"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.87/pentect-linux-x86_64"
      sha256 "0d926bab6bbea02b48afeabbdc11043aa4c71ecd07175b9be9d9838551ce6ca3"
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
