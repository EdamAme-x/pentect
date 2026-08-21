class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.44"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.44/pentect-macos-aarch64"
      sha256 "5bebabcc372a06c8e0e4a683290f11acbe8fa660cbf7ae648f00f24a6370dc5f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.44/pentect-macos-x86_64"
      sha256 "330754fb6b73060b8a2da93433dfd6f531a556df641929ae2955129ec975f7f5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.44/pentect-linux-aarch64"
      sha256 "53ec67aea2c829a56a842ff368b4c7400f752af63ad9612cae161af2fe4e0d4a"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.44/pentect-linux-x86_64"
      sha256 "bd92608c2b5ae0dbb98e0390b297d92a9e46335ef0e22c484acece217fcd1a91"
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
