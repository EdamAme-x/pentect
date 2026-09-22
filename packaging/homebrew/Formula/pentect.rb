class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.91"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.91/pentect-macos-aarch64"
      sha256 "f01c00226733c83d982943d05f33b2bbc30f75ee5ede5929ed54a10b77e86efc"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.91/pentect-macos-x86_64"
      sha256 "2c7b363600935d15698bc0e371d305b0a4d11ceb0690b5caf550f5fb3f0ce08b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.91/pentect-linux-aarch64"
      sha256 "fc6e16e32fea8ba23c5c5a77ce819bbe79cc00e63f532c42a40ab2a718dd0819"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.91/pentect-linux-x86_64"
      sha256 "68eb826f97b4a27fd063f329944861be43e8bec8e9a8113a634c6d8d701e79d4"
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
