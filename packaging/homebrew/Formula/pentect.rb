class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.46"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.46/pentect-macos-aarch64"
      sha256 "96a008eb84ac703de423cc0120875ed7b07878f53e05f8fe8d79dba54e5d9235"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.46/pentect-macos-x86_64"
      sha256 "75d07bafceca0ea6927686e144864463f981567d80d8c83a834d3204e725e68d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.46/pentect-linux-aarch64"
      sha256 "3b516357e26c66453b79d4d0ad2583ba63607871bb8e947c3736cfd7db4c3fb6"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.46/pentect-linux-x86_64"
      sha256 "25b830422ef6c1075dc6264db76660534e47e36fa883e71d2d4be7e66c5a509d"
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
