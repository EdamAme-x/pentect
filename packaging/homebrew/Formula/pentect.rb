class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.86"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.86/pentect-macos-aarch64"
      sha256 "99f824a32ca8e31d0d3b985c891c72abaa51b5dd05d7c013fce1dd5c1ae2539d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.86/pentect-macos-x86_64"
      sha256 "79144af9604f8e53ff1c3af98575882d87b4605e8e2d926d330c8cdc132b194f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.86/pentect-linux-aarch64"
      sha256 "f7798ebfb54049a9e724539722aed62374eb4cac143116fc6a30521f8bd0a582"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.86/pentect-linux-x86_64"
      sha256 "a092bcef7da20f4e002659df963a623c38ab09c50e7f761ac1f63785eae5dd5f"
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
