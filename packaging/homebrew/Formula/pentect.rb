class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.85"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.85/pentect-macos-aarch64"
      sha256 "99f808b3a0a9ff9f90423d8f4c2836ddd836cb4698e02ab629e50f5274413272"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.85/pentect-macos-x86_64"
      sha256 "cabd795e4a3c069f9f498a44379136530c595faca8fb14335b8cdc2a1f897a91"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.85/pentect-linux-aarch64"
      sha256 "73a21d5959c6d4071ca1aec87378f9db6961305948858f69c3fdce98f8276e05"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.85/pentect-linux-x86_64"
      sha256 "7b3601238322aebf834d07d1d29ff9a65b794055fb524c7ec1b1360d8c3e9f91"
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
