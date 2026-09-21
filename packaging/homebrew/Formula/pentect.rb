class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.90"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.90/pentect-macos-aarch64"
      sha256 "2c1e02ca3ceab3b6617ef6b1335c7a096f5df4b199a7965ebf054148ced752b7"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.90/pentect-macos-x86_64"
      sha256 "012a2a24b44dcd12da1cffed2a79a4aab90be17ef63ef9c26c1a344541236b67"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.90/pentect-linux-aarch64"
      sha256 "9241876655026f4a250b18989d38ff379b069c09053f189629d4994c1826b815"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.90/pentect-linux-x86_64"
      sha256 "526ebb59b1f821082e525a031eba5382ac338ccdc2f3796bcb01bd73610f5459"
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
