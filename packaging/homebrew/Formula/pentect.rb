class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.81"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.81/pentect-macos-aarch64"
      sha256 "84118cea50424d26a507db6d76c826d5d967a2b5a3d51fb350eff7befc2840cd"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.81/pentect-macos-x86_64"
      sha256 "55245060724aa19e76e3b21047573ea88d8259a1ca2c55b511f0b7538c6cdf67"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.81/pentect-linux-aarch64"
      sha256 "047fbc2c64efd72159a91628a8f092b271fc25d08ce26b48eeb4cb2d18bb5f46"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.81/pentect-linux-x86_64"
      sha256 "472c3b57572b651e2038de63ca76ff8e9f547873110f3a57cb562c1a6ef13e6a"
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
