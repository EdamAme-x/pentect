class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.80"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.80/pentect-macos-aarch64"
      sha256 "9de220cf928ab53137e6a56b9c769bac12a68f3a2b811e32793b3dc42838f9aa"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.80/pentect-macos-x86_64"
      sha256 "78264c02fdc5ccf15839c0a6595f7d6562db9c8b6f1da9e90046ec65b412fe93"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.80/pentect-linux-aarch64"
      sha256 "2e33f157ca70cad860e10f4a360011879c2a95587c213a876b13be6e3f74c9ea"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.80/pentect-linux-x86_64"
      sha256 "88c6161d0becf147c94058e941cb48a50bddec4158b6c2ab383bd1cffe50e367"
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
