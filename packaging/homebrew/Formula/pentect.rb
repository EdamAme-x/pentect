class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.60"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.60/pentect-macos-aarch64"
      sha256 "574b22a49a1c7f6b843f631d0808368d6459667f91256969d2c71b743d650bf2"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.60/pentect-macos-x86_64"
      sha256 "86fd9921f9ff658b8b61e447894c6f7a9160fa882e26eb5047b693517c6e137b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.60/pentect-linux-aarch64"
      sha256 "fa341c0dfa8c728b1bae45659240777d40c3f94b346d5529a15f873cb3f562cd"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.60/pentect-linux-x86_64"
      sha256 "506b8993daa6aebfad75671e7299ebb7f4d494b4af086949001d6d40a6774cec"
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
