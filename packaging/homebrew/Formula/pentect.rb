class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.62"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.62/pentect-macos-aarch64"
      sha256 "10f2958fabe9cdf1849c1e78fc0843da85fdafb6f80d5a157463b985f7a27e92"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.62/pentect-macos-x86_64"
      sha256 "7a4fe99cdd1ed4bc012f6c0cdfb3a932a4d61112d904dcc4b79e61a98a42f184"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.62/pentect-linux-aarch64"
      sha256 "88f678058f07b64d5b665f5a8660a38967b2728ffa54ea7705fbb527a466ea7c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.62/pentect-linux-x86_64"
      sha256 "896fb8a96147ccf22513d28a74d753ef596055bfb79b0c5e4ef5022d438a42ad"
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
