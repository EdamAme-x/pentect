class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.99"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.99/pentect-macos-aarch64"
      sha256 "c408d6fb0b2ce19802ffbf16ec6e91d247aa9e4cadc45988a00d39655da2209c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.99/pentect-macos-x86_64"
      sha256 "c397dbcc73e4fa3f3be4089bc4d27d574dcc74bf23d8f9d846b58c32ca54e404"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.99/pentect-linux-aarch64"
      sha256 "aa5516d2aef0273b004781fa597828aaad572c2072446866e3a728880609f4e5"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.99/pentect-linux-x86_64"
      sha256 "ec35a164be2beec8e0db9f697a42edfefda5157cbf793da6e94c9b1af9072d48"
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
