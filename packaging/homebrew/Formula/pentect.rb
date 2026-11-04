class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.100"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.100/pentect-macos-aarch64"
      sha256 "6a4350b9d6c6df4bb7a689bf15483197e81aadb319aa88c5c57c869cd0de07d4"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.100/pentect-macos-x86_64"
      sha256 "02540d9411ed139d7bda1bec99d7191e9c7cfe62ed2009976c060857b50ac1dd"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.100/pentect-linux-aarch64"
      sha256 "cffa59f762c1c5bcb8820d217959faaded61806c9a24cdd13d6b7d3189460fb7"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.100/pentect-linux-x86_64"
      sha256 "d25820bf5bd912f838e731487806e4008e2a667d5e2e6fd735c943595eb45004"
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
