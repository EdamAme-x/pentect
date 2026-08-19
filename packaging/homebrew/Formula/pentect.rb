class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.35"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.35/pentect-macos-aarch64"
      sha256 "1c80dda93f2b19168f27d17d55ae495a3a9aa974e87b2df5049b1971c5850805"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.35/pentect-macos-x86_64"
      sha256 "1f7f6a78504c2cb626db2448913dc54e29723850961b5c5b7fbb0fb993c0dbf9"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.35/pentect-linux-aarch64"
      sha256 "4512458191e29b8f121b9e74625e6fa897dc012fb60197e7736d44ba450feb27"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.35/pentect-linux-x86_64"
      sha256 "4abe2a42df1f80b95ea974b604196706125c8421ad2df35ec83b0a3934f75d7f"
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
