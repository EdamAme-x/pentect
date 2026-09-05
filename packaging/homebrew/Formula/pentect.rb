class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.76"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.76/pentect-macos-aarch64"
      sha256 "ee43e0a3d8d110055ffd1a5fdcbeff56fd8db28f07b8118f83bc10b4e72e8850"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.76/pentect-macos-x86_64"
      sha256 "ee1bb71d26e604f50197dd9d4d13e623574a607f06bd4d55bcc2099ca301584d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.76/pentect-linux-aarch64"
      sha256 "7b312de276f155e4e550dbe31fbc1758033d59f5d1151524fed0bea5492b6e69"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.76/pentect-linux-x86_64"
      sha256 "71251417e93a27a6522bc3358bcf7c8b869ada1999128d6c5eb80c3236f36f39"
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
