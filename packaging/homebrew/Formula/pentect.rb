class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.95"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.95/pentect-macos-aarch64"
      sha256 "3d1697365a9b007e57e76f4cc760fb370d1638847553d896b9cdb810e95ba6ad"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.95/pentect-macos-x86_64"
      sha256 "3af0842122e2506215ee869608acee7bd112d2f6059c63581e1ed4f3ea56dd2f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.95/pentect-linux-aarch64"
      sha256 "2f990771cf020fc75c3b51b8b3990fa5cf6ee3815fe45d63fb78ece9a215e3e2"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.95/pentect-linux-x86_64"
      sha256 "b0773840910579c24d6db2ca516ac37608df7e7c640d12031a1b1834dfa53462"
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
