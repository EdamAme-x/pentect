class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.28"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.28/pentect-macos-aarch64"
      sha256 "ef70835d5c1d43047a097ee856811e97abe36a0657feed1eab9c5946e1a16301"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.28/pentect-macos-x86_64"
      sha256 "157f681bd6b483909e03a42d96e4da222b26127ca6e18439c04ed8d8a8144995"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.28/pentect-linux-aarch64"
      sha256 "8165963b0e11b449afd397752b9c681977ec2e6a9540ab17ba1ff8dfd0a5a35a"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.28/pentect-linux-x86_64"
      sha256 "bea25e9d3ba9b2c897e46cb34d92d7b9fa2c844731ccb3f6e19c82a7d9af39f4"
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
