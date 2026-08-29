class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.70"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.70/pentect-macos-aarch64"
      sha256 "e190283a9217d00a48a3d55da41cf98cbc8ac6f5769b01ab36f661f45ad85f7c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.70/pentect-macos-x86_64"
      sha256 "c2438c8b7ecfa950390898096818bf1f3c4290e672af73fbfe1f26b8c4f38bc4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.70/pentect-linux-aarch64"
      sha256 "001ae9e631e5e272df97c6f9300caf752bd645c3fc8ec0a0b32e4edc81ed76ca"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.70/pentect-linux-x86_64"
      sha256 "1f0f5ad7d4b07646e173fa37e6789c2b04808cd6154f03ab1918d4727d47bbca"
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
