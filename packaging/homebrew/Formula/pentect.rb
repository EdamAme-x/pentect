class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.66"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.66/pentect-macos-aarch64"
      sha256 "a3378f22297b2da33e2bab2db237031f2e85096107d151dde5786c4c74c903ae"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.66/pentect-macos-x86_64"
      sha256 "ae3048449e402dd4332afde28a0971f1eda7c02f2b613c714c43c57698efb417"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.66/pentect-linux-aarch64"
      sha256 "19c2aae03a342dca3cd73cca6756cec0d1bc30ffca234f4452cb6b050a31b366"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.66/pentect-linux-x86_64"
      sha256 "1eaeefbd22377c597d2bc51de672dfce5bca1f98d2bfa33d3745ae2d63af6fa0"
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
