class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.88"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.88/pentect-macos-aarch64"
      sha256 "7b1a316c72ac45c2cb03f0922beca5337a9bbbd31fe6292f1f9cb837a099e7d8"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.88/pentect-macos-x86_64"
      sha256 "e20d510e55b637886122545e4480a29f135ece9893adc290fc6bb3b2812dc0b5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.88/pentect-linux-aarch64"
      sha256 "c4b3ccb595c902b3fb55abac64a23c6b34ff6cabfb286ae43c058d2ca8b9a46f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.88/pentect-linux-x86_64"
      sha256 "40b7dfc25b6ae246cf2dda771611aaf430647c0ebb8e99d96157951fd5c977d6"
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
