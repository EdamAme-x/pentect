class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.101"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.101/pentect-macos-aarch64"
      sha256 "40f83c0ada81f8fe2fdb697d984f01e95f0bef80bb8c0d70441852d59a5341dc"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.101/pentect-macos-x86_64"
      sha256 "634c50d63ecec89bf37716436f39a7a5c0290a281763953a4a8df80dd6f7dfa6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.101/pentect-linux-aarch64"
      sha256 "c9eda43eb4d907a74b93413104a77bc0aef84f4d6b80f943133646385cdd1e66"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.101/pentect-linux-x86_64"
      sha256 "7cea17abd014430d1294e8a6afa9864d6af968bd50d91f19d10ae8f38eaa492a"
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
