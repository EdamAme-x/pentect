class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.54"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.54/pentect-macos-aarch64"
      sha256 "e24b53ee58689a835da5a387f72c7b8e56f3566765b7555d88e2e0d4e8740727"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.54/pentect-macos-x86_64"
      sha256 "990f1899c019b79f427c0302b93e0292d40245463c5f6b4782f16ea50e129579"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.54/pentect-linux-aarch64"
      sha256 "3fa333efc193457ad32bc57283b559c48447602774dd2e15ac373aa13bac9d0b"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.54/pentect-linux-x86_64"
      sha256 "986f4a10cc1856af47216134fac968eddfce4c75cda590b2bf8b2cadd83c73a9"
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
