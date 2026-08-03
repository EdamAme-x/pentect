class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.23"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.23/pentect-macos-aarch64"
      sha256 "2be506fec5f2c5b674369bc681eac39dcf2615d5d1583b1acbe0dff8a6392168"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.23/pentect-macos-x86_64"
      sha256 "875cfb7d4256e0c05dd1dfa56a8d00b6c5e0e676ed7053b5bdbab478379ecc2b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.23/pentect-linux-aarch64"
      sha256 "a9cf67d626cdf4bb6adf36eb9229a15aacbd245e39c68d6e0ab76d8a70c37a82"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.23/pentect-linux-x86_64"
      sha256 "57ad2f1c23bcd32160376eede5bf3b135d1b82c58f2b865d077fb9462e2aa811"
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
