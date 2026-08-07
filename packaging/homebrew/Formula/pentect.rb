class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.27"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.27/pentect-macos-aarch64"
      sha256 "662313d554e9ce4afa3d8a73d1042f3fcbe16bca0d19828b6da5c59fd0ca4088"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.27/pentect-macos-x86_64"
      sha256 "b163e306f6ddb2d5eb46945fd2974e1a22ef8ee80367e883509370e061321525"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.27/pentect-linux-aarch64"
      sha256 "3625a9978f3be05d6eef903e1de108cf8002582bdb3cd45d0d69b12c9d233e2b"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.27/pentect-linux-x86_64"
      sha256 "6b9a152d04be08a9077e54cd8b58ccf194f6ee3e0555d0cfeb5fee73b5f43f12"
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
