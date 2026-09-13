class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.84"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.84/pentect-macos-aarch64"
      sha256 "705c65ca5172bc2387078ad60bf7350a34d643a6e6bc07f7174539778ef5d801"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.84/pentect-macos-x86_64"
      sha256 "fc8516a71ab4b6eb2f20b69c6e9e4011a4e8e74610025e0bb3aac20b542b1532"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.84/pentect-linux-aarch64"
      sha256 "741b176d2bedbbb5e907b88981722f6f2a67b0ce417c8a2c2dc130846cd038ff"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.84/pentect-linux-x86_64"
      sha256 "df3c95f21c535b394642d6a90614d0b19b73040bee96cf0826297dd3dee802f3"
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
