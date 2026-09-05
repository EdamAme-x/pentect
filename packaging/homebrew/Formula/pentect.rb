class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.75"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.75/pentect-macos-aarch64"
      sha256 "e07114dfd0ff8d9e3b40d6d9be9ce671e52a3c0030138612167d17e52da89270"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.75/pentect-macos-x86_64"
      sha256 "1d8677cffd15c493ae21bbb2ec0e76527a6be6abd5dfb65c3e048a39f1c94044"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.75/pentect-linux-aarch64"
      sha256 "66859c1bc5afdeec4543eacac2d069212db6de11ee1ebad12b1282fcd18dabeb"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.75/pentect-linux-x86_64"
      sha256 "a969355974a93d389dcbbcd31469a57f507314ab91e18106c0f2b5322ae34eb6"
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
