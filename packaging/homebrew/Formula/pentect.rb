class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.72"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.72/pentect-macos-aarch64"
      sha256 "94722fec90554826609dde860048613e3bc9a467c03180b5adcf51efefd1a8b6"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.72/pentect-macos-x86_64"
      sha256 "a4460f3aaabafa2d2a41f5d18513aeb2ebcee3698addc6d457b9a8e2e02a6363"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.72/pentect-linux-aarch64"
      sha256 "6cecc4f31d9da631f4d8d250480798c95eb6c1150829d1fa870dcd21bda64b63"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.72/pentect-linux-x86_64"
      sha256 "d57acb676fa731e0f51fb1e756e55268b2b40841e91cd430867959b8802c7380"
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
