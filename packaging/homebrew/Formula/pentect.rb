class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.89"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.89/pentect-macos-aarch64"
      sha256 "12293cc275e1cd79a20e148ad6de91695bdce3d28af6381abb3ee83578993a7c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.89/pentect-macos-x86_64"
      sha256 "ad0f884238024832867e694f345bd754beddfd3c280b925f4d25dfc8e76faa75"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.89/pentect-linux-aarch64"
      sha256 "5f7dd767d5edad8231450cea02361ce697a35d7c9447c78cc768cc8ad9e35495"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.89/pentect-linux-x86_64"
      sha256 "aae3e5912ffd5382cebd2f0bb9d62b175b79f5813e204a15c7c9df1d6b820dcf"
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
