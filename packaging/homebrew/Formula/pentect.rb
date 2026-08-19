class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.34"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.34/pentect-macos-aarch64"
      sha256 "94bec8f8a805d89672667743bc2e38dffa6f4a88c46cc4f4b02157ca4d189d74"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.34/pentect-macos-x86_64"
      sha256 "9b2c8fdd2b565ea5212a596c974ec1c975a1684ffbf404fda41835893eb127b3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.34/pentect-linux-aarch64"
      sha256 "60a1fb82ef187444b69eac98539fe03bf379402fdf0678a0c19bab6bd09e80da"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.34/pentect-linux-x86_64"
      sha256 "c231ef91f647d3b0b9ae5f42b2407b655ef45737b9f06668ea4592890671858d"
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
