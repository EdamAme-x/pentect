class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.67"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.67/pentect-macos-aarch64"
      sha256 "2afd25baa0f316d50eb0791bd5554674881e2061cd5c747ec7eeeef712de091f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.67/pentect-macos-x86_64"
      sha256 "a344f27f7bb987bf4642e92f4d32fe49c367f3933128ffa005972646063062c4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.67/pentect-linux-aarch64"
      sha256 "32c38226ce71fc68909c31657d8d5905bb7cc43d219620d2b49083e537e35c36"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.67/pentect-linux-x86_64"
      sha256 "4f0fc459d63d6183a3c0d033477a1a079c8af65c5b1e7c04ff9800fbe2c76b57"
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
